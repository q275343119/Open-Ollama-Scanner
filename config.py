# -*- coding: utf-8 -*-
# @Date     : 2025/2/26 10:59
# @Author   : q275343119
# @File     : config.py
# @Description:
import os

from dotenv import dotenv_values

# 加载 .env 文件的默认值
env_defaults = dotenv_values(".env")

# 定义最终的配置字典，优先使用环境变量，其次是 .env 文件的值，最后是代码内的默认值
settings = {
    "DATABASE_URL": os.getenv("DATABASE_URL", env_defaults.get("DATABASE_URL",
                                                               "postgresql://postgres:postgres@localhost:5432/ollama")),

}
__all__ = ["settings"]
