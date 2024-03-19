# fastapi-simple-jwt
一个FastApi简单的jwt验证

参考了官方文档修改而成

https://fastapi.tiangolo.com/zh/tutorial/security/first-steps/

## 前端可搭配Pure-admin使用

https://github.com/pure-admin/vue-pure-admin


## 安装

```
pip install fastapi-simple-jwt

```


## 使用

secret_key可使用 openssl rand -hex 32 生成


```
pip install -r requirements.txt

```

以下为简单案例，具体使用请参考 **auth.py**

```python
from fastapi_simple_jwt.simple_jwt import SimpleJWT, SecurityConfig  # 简单JWT以及安全设置类
from datetime import timedelta, datetime
from pydantic import BaseModel

security_config = SecurityConfig(
    # openssl rand -hex 32 生成
    secret_key='请使用自己的Key',
    # 默认为HS256
    algorithm='HS256',
    # 默认为True，Pure-Admin中需要设置为False，否则可能会遇到setToken失败的情况
    use_utc=False,
    # 默认访问Token有效期为30分钟
    access_token_expire=timedelta(minutes=30),
    # 默认刷新Token的有效期为7天，PureAdmin中储存在localStorage中，关闭浏览器失效
    refresh_token_expire=timedelta(days=7)
)

# JWT认证对象
AuthJWT = SimpleJWT(security_config)

# subject可以为用户名等信息
subject = {'username': 'admin', 'password': '123456'}
# 需要验证的Token
token = "abc.frazier.test"

# 创建accessToken
access_token = AuthJWT.create_access_token(subject=subject)

# 创建refreshToken
refresh_token = AuthJWT.create_refresh_token(subject=subject)

# 创建验证Token和刷新Token
# 返回结构为：{"accessToken": accessToken, "refreshToken": refreshToken}
token_dict = AuthJWT.create_access_and_refresh_token(subject=subject)

# 验证Token有效性
# 返回中会match字段解码失败或者类型不匹配均为False
verify_result = AuthJWT.verify_token(token=token,token_type='access') 

```

