# 作者：Frazier
# 日期：2024-3-19
# 学习项目：

'''知识总结：

'''


def p(text: str = "", num: int = 20, log: str = "-", t: bool = False):
    if t:
        num = 30
        log = "="

    if text != "":
        print(log * num, text, log * num)
    else:
        print(log * num * 2)
