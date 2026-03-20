import os
from dotenv import load_dotenv

load_dotenv()

ESTAT_API_KEY = os.environ.get("ESTAT_API_KEY", "")

if not ESTAT_API_KEY:
    raise ValueError("ESTAT_API_KEY is not set. Please set it in .env file.")
