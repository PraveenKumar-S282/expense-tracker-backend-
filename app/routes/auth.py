from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import jwt
from datetime import datetime, timedelta
import bcrypt
from app.database import get_connection
from dotenv import load_dotenv
import os

load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register")
def register(request: RegisterRequest):
    conn = get_connection()
    cursor = conn.cursor()

    hashed_pw = bcrypt.hashpw(
        request.password.encode("utf-8"),
        bcrypt.gensalt()
    )

    try:
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (request.email, hashed_pw)
        )

        conn.commit()

        return {
            "message": "User registered successfully"
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    finally:
        cursor.close()
        conn.close()


@router.post("/login")
def login(request: LoginRequest):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password FROM users WHERE email = %s",
            (request.email,)
        )

        user = cursor.fetchone()

        if not user:
            raise HTTPException(
                status_code=401,
                detail="User not found"
            )

        user_id = user[0]
        stored_password = user[1]

        # MySQL returns string sometimes
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        password_match = bcrypt.checkpw(
            request.password.encode("utf-8"),
            stored_password
        )

        if not password_match:
            raise HTTPException(
                status_code=401,
                detail="Invalid password"
            )

        secret_key = os.getenv("SECRET_KEY")

        if not secret_key:
            raise HTTPException(
                status_code=500,
                detail="SECRET_KEY not found in .env"
            )

        token = jwt.encode(
            {
                "user_id": user_id,
                "exp": datetime.utcnow() + timedelta(days=7)
            },
            secret_key,
            algorithm="HS256"
        )

        return {
            "user_id": user_id,
            "token": token
        }

    except Exception as e:
        print("LOGIN ERROR:", str(e))
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass