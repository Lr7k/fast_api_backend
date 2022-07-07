from decouple import config
from fastapi import HTTPException
from typing import Union
import motor.motor_asyncio
from bson import ObjectId
from auth_utils import AuthJwtCsrf


MONGO_API_KEY = config("MONGO_API_KEY")

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
database = client.API_DB

# mongo dbで設定したcollectionの名前と一致する必要がある
collection_todo = database.todo
collection_user = database.user

auth = AuthJwtCsrf()


def todo_serializer(todo) -> dict:
    """引数で受けとったtodoをdictに変換する"""
    return {
        "id": str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"],
    }


def user_serializer(user) -> dict:
    """引数で受け取ったユーザーデータをdictに変換する"""
    return {
        "id": str(user["_id"]),
        "email": user["email"]
    }


async def db_create_todo(data: dict) -> Union[dict, bool]:
    """todoを作成する"""
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})
    if new_todo:
        return todo_serializer(new_todo)
    return False


async def db_get_todos() -> list:
    """todoを取得する"""
    return [todo_serializer(e) for e in await collection_todo.find().to_list(length=100)]


async def db_get_single_todo(id: str) -> Union[dict, bool]:
    """一つのtodoを取得する"""
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        return todo_serializer(todo)
    return False


async def db_update_todo(id: str, data: dict) -> Union[dict, bool]:
    """idで受け取ったtodoを更新する"""

    # idで既存データを確認
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:

        # 既存データを引数のdataで更新
        update_todo = await collection_todo.update_one({"_id": ObjectId(id)}, {"$set": data})
        if update_todo.modified_count > 0:
            new_todo = await collection_todo.find_one({"_id": ObjectId(id)})
            return todo_serializer(new_todo)
    return False


async def db_delete_todo(id: str) -> bool:
    """idで指定したtodoを削除する"""
    todo = await collection_todo.find_one({"_id": ObjectId(id)})
    if todo:
        deleted_todo = collection_todo.delete_one({"_id": ObjectId(id)})
        if deleted_todo.deleted_count > 0:
            return True
    return False


async def db_signup(data: dict) -> dict:
    """
    クライアントサイドから入力された値でユーザーの登録を行う
    """
    email = data.get("email")
    password = data.get("password")

    # すでにユーザーが登録されていないかの確認
    overlap_user = await collection_user.find_one({"email": email})
    if overlap_user:
        raise HTTPException(status_code=400, detail="Email is already taken")

    # passwordのバリデーション
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password too short")

    # 平文をhash化させDBに保存する
    user = await collection_user.insert_one({"email": email, "password": auth.generate_hashed_pw(password)})
    new_user = await collection_user.find_one({"_id": user.inserted_id})
    return user_serializer(new_user)


async def db_login(data: dict) -> str:
    """
    ユーザーから受け取ったemail passwordが正しいか確認
    確認後、jwttokenの発行を行う
    """
    email = data.get("email")
    password = data.get("password")
    user = await collection_user.find_one({"email": email})
    if not user or not auth.verify_pw(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = auth.encode_jwt(user["email"])
    return token
