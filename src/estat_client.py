import httpx

from src.config import ESTAT_APP_ID

BASE_URL = "https://api.e-stat.go.jp/rest/3.0/app/json"


def _require_app_id() -> str:
    if not ESTAT_APP_ID:
        raise ValueError("ESTAT_APP_ID is not set. Please set it in .env file.")
    return ESTAT_APP_ID


class EStatAPIError(Exception):
    """e-Stat APIがエラーステータスを返した場合の例外"""

    def __init__(self, status: str, error_msg: str):
        self.status = status
        self.error_msg = error_msg
        super().__init__(f"e-Stat API error [{status}]: {error_msg}")


def _check_api_status(data: dict) -> None:
    result = data.get("GET_STATS_LIST") or data.get("GET_STATS_DATA") or data.get("GET_META_INFO")
    if result is None:
        return
    param = result.get("PARAMETER") or {}
    status = str(result.get("RESULT", {}).get("STATUS", "0"))
    error_msg = result.get("RESULT", {}).get("ERROR_MSG", "")
    if status != "0":
        raise EStatAPIError(status, error_msg)


def get_stats_list(
    search_word: str | None = None,
    stats_field: str | None = None,
    stats_code: str | None = None,
    start_position: int = 1,
    limit: int = 100,
) -> dict:
    """統計表一覧を取得する。

    Args:
        search_word: 検索キーワード
        stats_field: 統計分野コード（2桁）
        stats_code: 政府統計コード（5または8桁）
        start_position: データ取得開始位置（1始まり）
        limit: 最大取得件数（上限100000）
    """
    params: dict = {
        "appId": _require_app_id(),
        "lang": "J",
        "startPosition": start_position,
        "limit": limit,
    }
    if search_word:
        params["searchWord"] = search_word
    if stats_field:
        params["statsField"] = stats_field
    if stats_code:
        params["statsCode"] = stats_code

    with httpx.Client() as client:
        response = client.get(f"{BASE_URL}/getStatsList", params=params)
        response.raise_for_status()

    data = response.json()
    _check_api_status(data)
    return data


def get_stats_data(
    stats_data_id: str,
    start_position: int = 1,
    limit: int = 100000,
    cd_area: str | None = None,
    cd_time: str | None = None,
) -> dict:
    """統計データを取得する。

    Args:
        stats_data_id: 統計表ID
        start_position: データ取得開始位置（1始まり）
        limit: 最大取得件数
        cd_area: 地域コード
        cd_time: 時間軸コード
    """
    params: dict = {
        "appId": _require_app_id(),
        "lang": "J",
        "statsDataId": stats_data_id,
        "startPosition": start_position,
        "limit": limit,
    }
    if cd_area:
        params["cdArea"] = cd_area
    if cd_time:
        params["cdTime"] = cd_time

    with httpx.Client() as client:
        response = client.get(f"{BASE_URL}/getStatsData", params=params)
        response.raise_for_status()

    data = response.json()
    _check_api_status(data)
    return data


def get_meta_info(stats_data_id: str) -> dict:
    """統計表のメタ情報を取得する。

    Args:
        stats_data_id: 統計表ID
    """
    params = {
        "appId": _require_app_id(),
        "lang": "J",
        "statsDataId": stats_data_id,
    }

    with httpx.Client() as client:
        response = client.get(f"{BASE_URL}/getMetaInfo", params=params)
        response.raise_for_status()

    data = response.json()
    _check_api_status(data)
    return data
