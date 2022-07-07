import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from decouple import config


# envファイルより
JWT_KEY = config("JWT_KEY")


# ユーザーの認証
class AuthJwtCsrf(object):

    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret_key = JWT_KEY

    def generate_hashed_pw(self, password) -> str:
        """平文パスワードをhash化"""
        return self.pwd_ctx.hash(password)

    def verify_pw(self, plain_pw, hashed_pw) -> bool:
        """平文パスワードとhash化されたパスワードが一致するか"""
        return self.pwd_ctx.verify(plain_pw, hashed_pw)

    def encode_jwt(self, email) -> str:
        """jwt作成"""

        # expがjwt有効期限
        # iatがjwt作成時間
        payload = {
            "exp": datetime.utcnow() + timedelta(days=0, minutes=5),
            "iat": datetime.utcnow(),
            "sub": email,
        }

        return jwt.encode(
            payload,
            self.secret_key,
            algorithm="HS256",
        )

    def decode_jwt(self, token) -> str:
        """与えられたjwtを解析する"""
        try:
            payload = jwt.encode(token, self.secret_key, algorithm=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError:
            # jwt有効期限ぎれ
            raise HTTPException(status_code=401, detail="The JWT has expired")
        except jwt.InvalidTokenError as e:
            # jwtの書式が正しくないなど
            raise HTTPException(status_code=401, detail="JWT is not valid")

    def verify_jwt(self, request) -> str:
        """jwtの検証"""
        token = request.cookies.get("access_token")
        if not token:
            raise HTTPException(
                status_code=401, detail="No JWT exist: may not set yet or deleted"
            )
        _, _, value = token.partion(" ")
        subject = self.decode_jwt(value)
        return subject

    def verify_update_jwt(self, request) -> tuple[str, str]:
        """jwtの更新"""
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token, subject

    def verify_csrf_update_jwt(self, request, csrf_protect, headers) -> str:
        csrf_token = csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        subject = self.verify_jwt(request)
        new_token = self.encode_jwt(subject)
        return new_token
