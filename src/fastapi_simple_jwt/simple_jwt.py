from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union
from uuid import uuid4
from jose import jwt, JWTError
from pydantic import BaseModel
from abc import ABC

# 对外暴露
__all__ = [
    "SecurityConfig",
    "SimpleJWT",
]


# --------------------------------------
# 自定义类型


# 安全配置
class SecurityConfig(BaseModel):
    secret_key: str  # 安全密钥（加密解密的openssl rand -hex 32 生成）
    algorithm: str = jwt.ALGORITHMS.HS256  # 算法(默认HS256算法)
    use_utc: bool = True  # 是否使用UTC时间(默认使用，指定False为获取本地时间)
    access_token_expire: timedelta = timedelta(
        minutes=30)  # 访问Token过期时间（默认30分钟）
    refresh_token_expire: timedelta = timedelta(
        days=30)  # 刷新Token过期时间（默认7天，单位分钟）


# 创建令牌的返回值
class CreateTokenResult(BaseModel):
    token_str: str  # 加密后的token字符串
    token_type: str  # token类型（一般为access或者refresh）
    expires: datetime  # 过期时间
    create_time: datetime  # 创建时间
    uuid: str  # 唯一标识


# 解密令牌的返回值
class DecodeTokenResult(BaseModel):
    is_valid: bool = False
    subject: Union[Dict[str, Any], None] = None  # 子项
    type: Union[str, None] = None  # Token类别
    exp: Union[datetime, None] = None  # 有效时间
    iat: Union[datetime, None] = None  # 创建时间
    jti: Union[str, None] = None  # 唯一标识


# 验证令牌的返回值
class VerifyTokenResult(BaseModel):
    match: bool = False  # 解码失败或者类型不匹配均为False
    decode_token_result: Union[DecodeTokenResult, None] = None  # 解码失败则不会有
    # 如果刷新Token有效则会生成新的访问及刷新Token
    accessToken: Union[CreateTokenResult, None] = None
    refreshToken: Union[CreateTokenResult, None] = None


# --------------------------------------
# 功能区


class SimpleJWT(ABC):
    # 初始化
    def __init__(
            self,
            security_config: SecurityConfig
    ):
        self.secret_key = security_config.secret_key
        self.algorithm = security_config.algorithm
        self.use_utc = security_config.use_utc
        self.access_expires_delta = security_config.access_token_expire or timedelta(
            minutes=30)
        self.refresh_expires_delta = security_config.refresh_token_expire or timedelta(
            days=7)

    # -------------创建Token---------------
    # 创建AccessToken
    def create_access_token(
            self,
            subject: Dict[str, Any],  # 自定义子项
            expires_delta: Optional[timedelta] = None,  # 过期时间（不传则默认初始化时的数据）
            unique_identifier: Optional[str] = None,  # 唯一ID（不传则使用uuid4生成）
    ) -> Optional[CreateTokenResult]:  # 指定返回类型
        # 生成待加密的数据
        token_dict = self._generate_payload(
            subject=subject,
            expires_delta=expires_delta or self.access_expires_delta,
            unique_identifier=unique_identifier or str(uuid4()),
            token_type='access'
        )

        # 对数据进行加密
        jwt_encoded: str = jwt.encode(
            token_dict, self.secret_key, algorithm=self.algorithm
        )

        # 构建返回项
        return_obj = CreateTokenResult(
            token_str=jwt_encoded,  # 加密后的token字符串
            token_type='access',  # token类型（一般为access或者refresh）
            expires=token_dict.get('exp'),  # 过期时间
            create_time=token_dict.get('iat'),  # 创建时间
            uuid=token_dict.get('jti')  # 唯一标识
        )
        return return_obj

    # 创建RefreshToken
    def create_refresh_token(
            self,
            subject: Dict[str, Any],  # 自定义子项
            # 过期时间（不传则默认初始化时的数据）
            expires_delta: Optional[timedelta] = None,
            # 唯一ID（不传则使用uuid4生成）
            unique_identifier: Optional[str] = None,
    ) -> Optional[CreateTokenResult]:  # 指定返回类型
        # 生成待加密的数据
        token_dict = self._generate_payload(
            subject=subject,
            expires_delta=expires_delta or self.refresh_expires_delta,
            unique_identifier=unique_identifier or str(uuid4()),
            token_type='refresh'
        )

        # 对数据进行加密
        jwt_encoded: str = jwt.encode(
            token_dict, self.secret_key, algorithm=self.algorithm
        )

        # 构建返回项
        return_obj = CreateTokenResult(
            token_str=jwt_encoded,  # 加密后的token字符串
            token_type='refresh',  # token类型（一般为access或者refresh）
            expires=token_dict.get('exp'),  # 过期时间
            create_time=token_dict.get('iat'),  # 创建时间
            uuid=token_dict.get('jti')  # 唯一标识
        )
        return return_obj

    def _generate_payload(
            self,
            subject: Dict[str, Any],
            expires_delta: timedelta,
            unique_identifier: str,
            token_type: str,
    ) -> Dict[str, Any]:
        # 建议修改前端使用UTC，未测试jwt.decode函数中是否会因为时区不同导致结果不准确
        # https://blog.csdn.net/weixin_43726448/article/details/125636737
        if self.use_utc:
            now = datetime.utcnow()
        else:
            now = datetime.now()

        return {
            "subject": subject.copy(),  # 存储用户信息（用户名等）
            "type": token_type,  # Token类别，区分访问Token和刷新Token
            "exp": now + expires_delta,  # 过期时间（jwt.encode需要 exp 项生成过期时间时间签名）
            "iat": now,  # 创建时间（签发时间）
            "jti": unique_identifier,  # 唯一标识
        }

    # 创建验证Token和刷新Token
    def create_access_and_refresh_token(
            self,
            subject: Dict[str, Any],  # 自定义子项
    ):
        accessToken = self.create_access_token(subject)  # 验证Token
        refreshToken = self.create_refresh_token(subject)  # 刷新Token

        return {"accessToken": accessToken, "refreshToken": refreshToken}

    # -------------解密Token---------------
    # 解密Token并格式化返回

    def _decode_token(self, token: str) -> Optional[DecodeTokenResult]:
        # 构建待返回内容
        return_dict = {
            "is_valid": False,
            "subject": None,
            "type": None,
            "exp": None,
            "iat": None,  # 创建时间
            "jti": None  # 唯一标识
        }
        try:
            payload = jwt.decode(token, self.secret_key,
                                 algorithms=self.algorithm)

            # 如果验证成功则更新字典
            return_dict.update({"is_valid": True})
            return_dict.update(payload)

        # 如果验证失败则返回
        except JWTError as e:
            print(e)

        # 构建返回值
        return DecodeTokenResult(**return_dict)

    # 验证Token有效性
    def verify_token(
            self,
            token: str,
            token_type: str = "access"
    ) -> Optional[VerifyTokenResult]:
        # 如果token获取失败则直接返回
        if not token:
            return VerifyTokenResult(match=False)

        # 对传入的Token进行解码
        decode_token_result = self._decode_token(token)
        # 如果解码失败
        if not decode_token_result.is_valid:
            return_result = VerifyTokenResult(match=False)
        else:
            # 如果解码成功，则判断类型是否匹配
            if decode_token_result.type == token_type == "access":
                # 如果都是访问Token则返回成功，并且创建新的Token返回
                return_result = VerifyTokenResult(
                    match=True,
                    decode_token_result=decode_token_result
                )
            elif decode_token_result.type == token_type == "refresh":
                # 如果都是刷新Token则返回成功，并且创建新的Token返回
                return_result = VerifyTokenResult(
                    match=True,
                    accessToken=self.create_access_token(decode_token_result.subject),
                    refreshToken=self.create_refresh_token(decode_token_result.subject)
                )
            else:
                # 如果类型匹配失败，则返回失败，并且携带解密后的数据（可考虑拉入黑名单）
                return_result = VerifyTokenResult(
                    match=False,
                    decode_token_result=decode_token_result
                )
        # print(return_result)
        return return_result
