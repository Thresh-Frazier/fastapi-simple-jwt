# 主要是为PureAdmin做后端的JWT匹配
# 但是要注意的是PureAdmin中使用的是当前时间，SimpleJWT使用的是UTC时间，建议初始化SecurityConfig时将use_utc设置为False

from src.fastapi_simple_jwt.simple_jwt import SimpleJWT, SecurityConfig  # 简单JWT以及安全设置类
from src.fastapi_simple_jwt.match_login import authenticate_user, User  # 登录匹配
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials  # 从请求头中获取Token
from fastapi import APIRouter  # 导出路由，报错
from settings import JWTSettings  # 安全配置
from fake_users import fake_users_db  # 假的数据
from pydantic import BaseModel  # 自定义类型
from typing import Union, List  # 结合BaseModel使用
from datetime import timedelta  # 时间间隔
# 从请求头的Authorization字段中获取Token
from fastapi import Depends

# 导出路由
auth_router = APIRouter()

# 初始化相关
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl='auth/login')  # 从请求头中获取Token
oauth2_scheme = HTTPBearer()  # 从请求头中获取Token
# 安全配置类
security_config = SecurityConfig(
    secret_key=JWTSettings.secret_key,
    algorithm=JWTSettings.algorithm,
    use_utc=JWTSettings.use_utc,
    access_token_expire=timedelta(
        minutes=JWTSettings.access_token_expire_minutes),
    refresh_token_expire=timedelta(
        minutes=JWTSettings.refresh_token_expire_minutes)
)
# JWT认证对象
AuthJWT = SimpleJWT(security_config)


# ---------------------自定义数据结构-----------------------


# 登录结构
class LoginData(BaseModel):
    username: str
    password: str


# 刷新Token的传入值
class RefreshData(BaseModel):
    refreshToken: str


# 刷新返回样式
class RefreshTokenData(BaseModel):
    accessToken: str
    refreshToken: str
    expires: str  # datetime.strftime(datetime, "%Y-%m-%d %H:%M:%S")


# 登录返回样式
class AccessTokenData(RefreshTokenData):
    username: str
    roles: List


# 返回数据类，可能为登录或刷新Token的结构
class ReturnData(BaseModel):
    success: bool = False
    data: Union[RefreshTokenData, AccessTokenData]


# ---------------------自定义验证函数-----------------------
async def get_current_user(token: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """
    验证Token的有效性，并返回用户信息
    :param token: 从请求头中获取的Token
    :return: 用户信息
    """
    # 初始化待返回的字典
    user_dict = {
        'username': "",
        'nickname': None,
        'is_active': None,  # 账户启用
        'roles': None,  # 拥有权限
    }

    # 验证Token的有效性
    token_result = AuthJWT.verify_token(token.credentials, token_type="access")
    # 如果Token无效或获取失败
    if not token or not token_result.match:
        # raise HTTPException(status_code=401, detail='Token无效')
        pass
    else:
        # 如果Token有效则从数据库返回获取到的用户信息
        user_dict = fake_users_db[token_result.decode_token_result.subject.get('username')]
        print(user_dict)
    return User(**user_dict)


# -----------------页面-----------------
@auth_router.post("/login", response_model=ReturnData)
async def auth(login_data: LoginData):
    """
    用户登录接口
    :param login_data: 用户名和密码
    :return: 登录成功后返回的Token
    """
    # 构建默认返回结构
    return_dict = {
        "success": False,
        "data": {
            "username": "",
            "roles": [],
            "accessToken": "",
            "refreshToken": "",
            "expires": "1999/12/31 23:59:59",
        }
    }

    # 定义一个异步函数来处理登录请求，使用OAuth2PasswordRequestForm自动解析请求体。
    user = authenticate_user(
        fake_users_db, login_data.username, login_data.password)
    # 调用authenticate_user函数，验证用户的用户名和密码是否有效。
    if not user:
        # 如果用户认证失败（即authenticate_user返回False）直接返回默认返回字典
        pass
        # raise HTTPException(status_code=400, detail="Incorrect username or password")
        # 抛出HTTP异常，状态码设置为400，错误详情为"Incorrect username or password"。

    else:
        # subject（实际负载）是任何可使用json的python dict
        subject = {"username": user.username, "roles": user.roles}

        # 创建新的访问/刷新令牌对
        token_dict = AuthJWT.create_access_and_refresh_token(subject=subject)

        # 更新返回结构
        return_dict = {
            "success": True,
            "data": {
                "username": user.username,
                "roles": user.roles,
                "accessToken": token_dict.get('accessToken').token_str,
                "refreshToken": token_dict.get('refreshToken').token_str,
                "expires": token_dict.get('accessToken').expires.strftime("%Y/%m/%d %H:%M:%S"),
            }
        }
        print(user.username + "登录成功")
    print(return_dict)
    return return_dict


@auth_router.post("/refresh-token", response_model=ReturnData)
async def refresh(
        refresh_data: RefreshData  # 接收自定义前端Post过来的结构
):
    """
    刷新令牌
    :param refresh_data:刷新Token
    :return: ReturnData类
    """
    # 构建默认返回结构
    return_dict = {
        "success": False,
        "data": {
            "accessToken": "",
            "refreshToken": "",
            "expires": "1999/12/31 23:59:59",
        }
    }
    verify_result = AuthJWT.verify_token(
        refresh_data.refreshToken, token_type='refresh')

    # 如果验证成功
    if verify_result.match:
        # 组合新的Token作为返回
        # 更新返回结构
        return_dict = {
            "success": True,
            "data": {
                "accessToken": verify_result.accessToken.token_str,
                "refreshToken": verify_result.refreshToken.token_str,
                "expires": verify_result.accessToken.expires.strftime("%Y/%m/%d %H:%M:%S")
            }
        }
    else:
        # 验证失败直接返回空信息
        pass

    return return_dict


@auth_router.get("/users/me")
async def read_current_user(
        current_user: User = Depends(get_current_user)
):
    """
    获取当前用户信息
    :param current_user: 从JWT中获取当前用户信息，调用get_current_user函数返回而来
    :return:
    """
    return current_user

    # now we can access Credentials object
