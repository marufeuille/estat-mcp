from unittest.mock import patch

import pytest

from src.server import mcp


def test_tools_registered():
    tools = mcp._tool_manager.list_tools()
    names = {t.name for t in tools}
    assert "tool_get_stats_list" in names
    assert "tool_get_stats_data" in names
    assert "tool_get_meta_info" in names


STATS_LIST_OK = {
    "GET_STATS_LIST": {
        "RESULT": {"STATUS": 0, "ERROR_MSG": "正常終了"},
        "PARAMETER": {},
        "DATALIST_INF": {"NUMBER": 1, "TABLE_INF": []},
    }
}

STATS_DATA_OK = {
    "GET_STATS_DATA": {
        "RESULT": {"STATUS": 0, "ERROR_MSG": "正常終了"},
        "PARAMETER": {},
        "STATISTICAL_DATA": {},
    }
}

META_INFO_OK = {
    "GET_META_INFO": {
        "RESULT": {"STATUS": 0, "ERROR_MSG": "正常終了"},
        "PARAMETER": {},
        "METADATA_INF": {},
    }
}


@patch("src.server.get_stats_list", return_value=STATS_LIST_OK)
def test_tool_get_stats_list_success(mock_fn):
    from src.server import tool_get_stats_list
    result = tool_get_stats_list(search_word="人口")
    assert "GET_STATS_LIST" in result
    mock_fn.assert_called_once()


@patch("src.server.get_stats_data", return_value=STATS_DATA_OK)
def test_tool_get_stats_data_success(mock_fn):
    from src.server import tool_get_stats_data
    result = tool_get_stats_data(stats_data_id="0003448237")
    assert "GET_STATS_DATA" in result


@patch("src.server.get_meta_info", return_value=META_INFO_OK)
def test_tool_get_meta_info_success(mock_fn):
    from src.server import tool_get_meta_info
    result = tool_get_meta_info(stats_data_id="0003448237")
    assert "GET_META_INFO" in result


@patch("src.server.get_stats_list", side_effect=__import__("src.estat_client", fromlist=["EStatAPIError"]).EStatAPIError("100", "不正なパラメータ"))
def test_tool_returns_error_dict_on_api_error(mock_fn):
    from src.server import tool_get_stats_list
    result = tool_get_stats_list()
    assert "error" in result
    assert result["status"] == "100"
