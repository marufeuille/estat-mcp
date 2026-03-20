import os
from dotenv import load_dotenv

load_dotenv()

ESTAT_APP_ID = os.environ.get("ESTAT_APP_ID", "")
