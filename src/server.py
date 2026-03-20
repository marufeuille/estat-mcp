from mcp.server.fastmcp import Context, FastMCP

from src.auth import check_permission
from src.estat_client import EStatAPIError, get_meta_info, get_stats_data, get_stats_list

mcp = FastMCP("estat-mcp")


@mcp.tool()
def tool_get_stats_list(
    ctx: Context,
    search_word: str | None = None,
    stats_field: str | None = None,
    stats_code: str | None = None,
    start_position: int = 1,
    limit: int = 100,
) -> dict:
    """e-Stat APIから統計表一覧を取得する。

    Args:
        search_word: 検索キーワード（例: "人口", "労働力"）
        stats_field: 統計分野コード（2桁、例: "02" = 人口・世帯）
        stats_code: 政府統計コード（5または8桁）
        start_position: 取得開始位置（1始まり）
        limit: 最大取得件数（上限100000）
    """
    request = ctx.request_context.request if ctx.request_context else None
    ok, reason = check_permission("tool_get_stats_list", request=request)
    if not ok:
        return {"error": reason}

    try:
        return get_stats_list(
            search_word=search_word,
            stats_field=stats_field,
            stats_code=stats_code,
            start_position=start_position,
            limit=limit,
        )
    except EStatAPIError as e:
        return {"error": str(e), "status": e.status}


@mcp.tool()
def tool_get_stats_data(
    ctx: Context,
    stats_data_id: str,
    start_position: int = 1,
    limit: int = 100000,
    cd_area: str | None = None,
    cd_time: str | None = None,
) -> dict:
    """e-Stat APIから統計データを取得する。

    Args:
        stats_data_id: 統計表ID（例: "0003448237"）
        start_position: 取得開始位置（1始まり）
        limit: 最大取得件数
        cd_area: 地域コード（例: "13" = 東京都）
        cd_time: 時間軸コード（例: "2020000000"）
    """
    request = ctx.request_context.request if ctx.request_context else None
    ok, reason = check_permission("tool_get_stats_data", request=request)
    if not ok:
        return {"error": reason}

    try:
        return get_stats_data(
            stats_data_id=stats_data_id,
            start_position=start_position,
            limit=limit,
            cd_area=cd_area,
            cd_time=cd_time,
        )
    except EStatAPIError as e:
        return {"error": str(e), "status": e.status}


@mcp.tool()
def tool_get_meta_info(ctx: Context, stats_data_id: str) -> dict:
    """e-Stat APIから統計表のメタ情報（分類・時間軸など）を取得する。

    Args:
        stats_data_id: 統計表ID（例: "0003448237"）
    """
    request = ctx.request_context.request if ctx.request_context else None
    ok, reason = check_permission("tool_get_meta_info", request=request)
    if not ok:
        return {"error": reason}

    try:
        return get_meta_info(stats_data_id=stats_data_id)
    except EStatAPIError as e:
        return {"error": str(e), "status": e.status}


def main():
    import uvicorn

    from src.middleware import SessionRoleMiddleware

    base_app = mcp.sse_app()
    app = SessionRoleMiddleware(base_app)
    uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port)


if __name__ == "__main__":
    main()
