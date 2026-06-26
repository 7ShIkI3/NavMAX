"""Authentification JWT, RBAC, et hash des mots de passe pour NavMAX API.

Fonctionnalités :
  - Génération et validation de tokens JWT
  - Hash des mots de passe avec bcrypt (via passlib)
  - RBAC : admin, operator, viewer
  - Dépendances FastAPI pour protéger les routes
  - Rate limiting via slowapi
  - Fallback in-memory si Redis indisponible
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from navmax.core.config import config
from navmax.core.logging import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration JWT
# ---------------------------------------------------------------------------
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 heure

# Clé secrète — en prod, utiliser une variable d'environnement NAVMAX_JWT_SECRET
SECRET_KEY: str = config.jwt_secret or "ch@ng3-me-1n-pr0duct10n-2024-navmax"

if len(SECRET_KEY) < 32:
    msg = "NAVMAX_JWT_SECRET doit faire au moins 32 caractères pour la sécurité"
    raise ValueError(
        msg,
    )

# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt.

    Args:
        password: Mot de passe en clair.

    Returns:
        Hash bcrypt du mot de passe.

    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe contre son hash.

    Args:
        plain_password: Mot de passe en clair.
        hashed_password: Hash bcrypt stocké.

    Returns:
        True si le mot de passe correspond.

    """
    return pwd_context.verify(plain_password, hashed_password)


# ---------------------------------------------------------------------------
# Modèle User
# ---------------------------------------------------------------------------


class User(BaseModel):
    """Utilisateur NavMAX avec rôle et statut."""

    username: str
    hashed_password: str
    role: str = Field(pattern="^(admin|operator|viewer)$")
    disabled: bool = False


# Base de données utilisateurs en mémoire (remplacer par une vraie BDD en prod)
_users_db: dict[str, User] = {}


def get_user(username: str) -> User | None:
    """Récupère un utilisateur depuis le store.

    Args:
        username: Nom d'utilisateur.

    Returns:
        Instance User ou None si introuvable.

    """
    return _users_db.get(username)


def create_user(username: str, password: str, role: str = "viewer") -> User:
    """Crée un nouvel utilisateur.

    Args:
        username: Nom d'utilisateur.
        password: Mot de passe en clair.
        role: Rôle (admin|operator|viewer).

    Returns:
        Instance User créée.

    """
    user = User(
        username=username,
        hashed_password=hash_password(password),
        role=role,
    )
    _users_db[username] = user
    return user


# Créer un admin par défaut au démarrage
_default_admin = create_user("admin", "admin123", "admin")
_default_operator = create_user("operator", "operator123", "operator")
_default_viewer = create_user("viewer", "viewer123", "viewer")

logger.info(
    "utilisateurs_par_défaut_créés",
    admin=_default_admin.username,
    operator=_default_operator.username,
    viewer=_default_viewer.username,
)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    """Crée un token JWT signé.

    Args:
        data: Données à encoder dans le token (doit contenir 'sub').
        expires_delta: Durée de validité (défaut : ACCESS_TOKEN_EXPIRE_MINUTES).

    Returns:
        Token JWT encodé.

    """
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Décode et valide un token JWT.

    Args:
        token: Token JWT à décoder.

    Returns:
        Payload du token.

    Raises:
        HTTPException: Si le token est invalide ou expiré.

    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Dépendances FastAPI
# ---------------------------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> User:
    """Dépendance FastAPI — extrait et valide l'utilisateur depuis le JWT.

    Vérifie que le header Authorization: Bearer <token> est présent,
    décode le token, et retourne l'utilisateur correspondant.

    Raises:
        HTTPException 401: Si le token est manquant, invalide ou expiré.
        HTTPException 401: Si l'utilisateur est désactivé.

    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise — header 'Authorization: Bearer <token>' manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    username: str | None = payload.get("sub")
    if username is None:
        logger.warning("auth_échec", raison="sub_manquant_dans_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide : 'sub' manquant",
        )

    user = get_user(username)
    if user is None:
        logger.warning("auth_échec", user=username, raison="utilisateur_introuvable")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur introuvable",
        )

    if user.disabled:
        logger.warning("auth_échec", user=username, raison="compte_désactivé")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé",
        )

    logger.info("auth_succès", user=username)
    return user


def require_role(required_role: str):
    """Fabrique une dépendance FastAPI qui vérifie le rôle.

    Les rôles sont hiérarchiques : admin > operator > viewer.
    Un admin peut tout faire, un operator peut ce que viewer peut + actions,
    un viewer ne peut que lire.

    Args:
        required_role: Rôle requis (admin|operator|viewer).

    Returns:
        Dépendance FastAPI qui lève HTTPException 403 si le rôle est insuffisant.

    """
    role_hierarchy = {"admin": 3, "operator": 2, "viewer": 1}

    async def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_level = role_hierarchy.get(current_user.role, 0)
        required_level = role_hierarchy.get(required_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Rôle insuffisant — requis '{required_role}', vous avez '{current_user.role}'"
                ),
            )
        return current_user

    return _role_checker


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------

# Fallback : si Redis n'est pas dispo, slowapi utilise le store in-memory
limiter = Limiter(key_func=get_remote_address)

# Limiteurs pré-configurés
auth_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10/minute"],  # 10 tentatives de login/min
)

# ---------------------------------------------------------------------------
# Schémas de requête / réponse
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    """Requête de connexion."""

    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """Réponse avec token JWT."""

    access_token: str
    token_type: str = "bearer"
    role: str


class RegisterRequest(BaseModel):
    """Requête d'inscription."""

    username: str = Field(..., min_length=3, max_length=255, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8)
    role: str = Field("viewer", pattern="^(admin|operator|viewer)$")


class RegisterResponse(BaseModel):
    """Réponse d'insscription."""

    username: str
    role: str
    message: str


# ---------------------------------------------------------------------------
# Routes d'authentification
# ---------------------------------------------------------------------------

auth_router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


@auth_router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest):
    """Authentifie un utilisateur et retourne un token JWT.

    Valide les credentials (username + password) et génère
    un token JWT signé contenant le username, le rôle, et la date d'expiration.
    """
    user = get_user(req.username)
    if user is None:
        logger.warning("auth_échec", user=req.username, raison="credentials_invalides")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
        )

    if not verify_password(req.password, user.hashed_password):
        logger.warning("auth_échec", user=req.username, raison="credentials_invalides")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
        )

    if user.disabled:
        logger.warning("auth_échec", user=req.username, raison="compte_désactivé")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé",
        )

    token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
        },
    )

    logger.info("auth_succès", user=req.username, role=user.role)
    return TokenResponse(access_token=token, role=user.role)


@auth_router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(req: RegisterRequest):
    """Crée un nouveau compte utilisateur.

    Note : en production, cet endpoint devrait être protégé par un token admin.
    Pour l'instant, accessible sans auth pour faciliter le développement.
    """
    if get_user(req.username) is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"L'utilisateur '{req.username}' existe déjà",
        )

    user = create_user(req.username, req.password, req.role)
    logger.info("utilisateur_créé", username=user.username, role=user.role)

    return RegisterResponse(
        username=user.username,
        role=user.role,
        message="Compte créé avec succès",
    )


@auth_router.get("/me", response_model=dict)
async def me(current_user: Annotated[User, Depends(get_current_user)]):
    """Retourne les informations de l'utilisateur connecté."""
    return {
        "username": current_user.username,
        "role": current_user.role,
        "disabled": current_user.disabled,
    }
