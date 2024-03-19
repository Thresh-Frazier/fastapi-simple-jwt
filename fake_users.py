# 请确保键与值中间的username保持一致
fake_users_db = {
    "alice": {
        "nickname": "Alice",
        "username": "alice",
        # secret 加密后如下
        "hashed_password": '$2b$12$RzMXc31I8rzKElo2bbMgu.n8pdN1cM4vxgGPz3SlOZ.YHYKYvdInO',
        "is_active": True,  # 账户启用
        "roles": ['common'],  # 拥有权限
    },
}
