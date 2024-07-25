from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pymongo.errors import DuplicateKeyError
from app.models import UserCreate, User
from app.database import get_user_collection
from app.auth import get_password_hash, verify_password, create_access_token, decode_access_token

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    username = payload.get("sub")
    user = get_user_collection().find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return User(**user)

@router.post("/register", response_model=User)
def register(user: UserCreate):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    hashed_password = get_password_hash(user.password)
    user_data = user.dict()
    user_data.pop("password")
    user_data.pop("confirm_password")
    user_data["hashed_password"] = hashed_password

    # Check for unique username
    if get_user_collection().find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    try:
        get_user_collection().insert_one(user_data)
    except DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Email already registered")
    return User(**user_data)

@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_collection().find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user
