from fastapi import FastAPI
import uvicorn
from auth import auth_router
# 自定义swagger ui的CDN地址
from fastapi import applications

app = FastAPI()

# 引入jwt测试路由
app.include_router(
    auth_router,
    prefix='/auth',
    tags=['auth'],
)


@app.get("/")
def main():
    return {"msg": "HelloWorld"}


if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=58083)
