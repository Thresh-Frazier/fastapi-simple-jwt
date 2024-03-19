# 验证用户

from passlib.context import CryptContext  # 密码加密（本地只存储hash后的密码）
from pydantic import BaseModel
from typing import List, Union

# -------------------初始化相关-------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # 密码加密


# -------------------自定义数据类型-------------------
class User(BaseModel):
    username: str
    nickname: Union[str, None] = None
    is_active: Union[bool, None] = None  # 账户启用
    roles: Union[List, None] = None  # 拥有权限


class UserInDB(User):
    nickname: Union[str, None] = None
    roles: List[str]
    hashed_password: str
    is_active: bool


# -------------------登录验证-------------------

# 验证账号密码是否匹配
def authenticate_user(db, username: str, password: str) -> Union[UserInDB, bool]:
    # 检查用户名是否在数据库中
    def get_user(db, username: str) -> Union[UserInDB, None]:
        if username in db:
            # 获取用户字典
            user_dict = db[username]
            # 返回一个UserInDB对象，使用用户字典中的键值对作为参数
            return UserInDB(**user_dict)
        else:
            return None

    # 检测密码是否与本地存储的HASH密码匹配
    def verify_password(password, hashed_password) -> bool:
        # 使用pwd_context模块的verify方法来验证明文密码和哈希密码是否匹配
        return pwd_context.verify(password, hashed_password)

    # ---------------------------------
    # 从数据库中获取用户信息
    user = get_user(db, username)
    # 如果用户不存在或者密码验证失败，返回False
    if not user or not verify_password(password, user.hashed_password):
        return False
    # 如果验证成功，返回用户信息
    return user
