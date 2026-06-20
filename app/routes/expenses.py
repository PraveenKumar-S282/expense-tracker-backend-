from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from datetime import date
import jwt
from app.database import get_connection
import os

router = APIRouter(prefix="/api/expenses", tags=["expenses"])

class ExpenseRequest(BaseModel):
    amount: float
    category: str
    date: date

def verify_token(authorization: str):
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        return payload["user_id"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@router.post("/")
def add_expense(request: ExpenseRequest, authorization: str = Header(None)):
    user_id = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO expenses (user_id, amount, category, date) VALUES (%s, %s, %s, %s)",
        (user_id, request.amount, request.category, request.date)
    )
    conn.commit()
    expense_id = cursor.lastrowid
    
    cursor.close()
    conn.close()
    
    return {"id": expense_id, "success": True}

@router.get("/")
def get_expenses(authorization: str = Header(None)):
    user_id = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT id, amount, category, date FROM expenses WHERE user_id = %s ORDER BY date DESC",
        (user_id,)
    )
    expenses = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return [{"id": e[0], "amount": e[1], "category": e[2], "date": str(e[3])} for e in expenses]

@router.delete("/{expense_id}")
def delete_expense(expense_id: int, authorization: str = Header(None)):
    user_id = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM expenses WHERE id = %s AND user_id = %s", (expense_id, user_id))
    conn.commit()
    
    cursor.close()
    conn.close()
    
    return {"success": True}
@router.put("/{expense_id}")
def update_expense(expense_id: int, request: ExpenseRequest, authorization: str = Header(None)):
    user_id = verify_token(authorization)
    conn = get_connection()
    cursor = conn.cursor()
    
    # Verify user owns this expense
    cursor.execute("SELECT user_id FROM expenses WHERE id = %s", (expense_id,))
    result = cursor.fetchone()
    
    if not result or result[0] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Update expense
    cursor.execute(
        "UPDATE expenses SET amount = %s, category = %s, date = %s WHERE id = %s",
        (request.amount, request.category, request.date, expense_id)
    )
    conn.commit()
    
    cursor.close()
    conn.close()
    
    return {"success": True, "message": "Expense updated"}