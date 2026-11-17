from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError
from datetime import datetime, timedelta
import bcrypt

from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()   # load variables from .env

# Read them into Python variables
MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "cs3720db")
PORT = int(os.getenv("PORT","8000"))

client = MongoClient(MONGODB_URI)   # Initialize the MongoDB client using the URI
db = client[MONGODB_DB]     # Connect to the specific database using the DB variable name

app = FastAPI()

# ======== CONFIG FOR JWT ========
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120


# ======== BCRYPT HELPERS ========
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8")
    )

# ======== MONGODB USER COLLECTION ========
users_collection = db["users"]

def save_user_to_db(email: str, hashed_pw: str):
    # Insert document into MongoDB Atlas
    users_collection.insert_one({"email": email, "hashed_password": hashed_pw})

def get_user_by_email(email: str):
    # Query MongoDB Atlas for the user
    user = users_collection.find_one({"email": email})
    if not user:
        return None
    return {"email": user["email"], "hashed_password": user["hashed_password"]}

# ======== Pydantic MODELS ========
class UserCreate(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# ======== OAUTH2 SCHEME (WHERE TOKEN COMES FROM) ========
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ======== JWT HELPERS ========
def create_jwt_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ======== 1) Implement Signup (UPDATED SIGNUP ROUTE) ========
@app.post("/signup")
def signup(user: UserCreate):
    # Check MongoDB instead of dictionary
    existing_user = get_user_by_email(user.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_pw = hash_password(user.password)
    save_user_to_db(user.email, hashed_pw)
    return {"msg": "signup ok"}

# ======== 2) Implement Login ========
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm maps form fields to `form_data.username` and `form_data.password`
    db_user = get_user_by_email(form_data.username)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(form_data.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token({"sub": db_user["email"]})
    return {"access_token": token, "token_type": "bearer"}

# ======== 3) JWT Auth Dependency ========
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = get_user_by_email(email)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return email
    
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ======== 4) FastAPI Protected Route EXAMPLE ========
@app.get("/protected")
def read_protected_data(current_user: str = Depends(get_current_user)):
    # current_user is the email returned from get_current_user
    return {"msg": f"Hello {current_user}, this is protected data!"}


# ======== Simple Root (for testing) ========
@app.get("/hello")
def hello():
    return {"message": "Hello from FastAPI"}