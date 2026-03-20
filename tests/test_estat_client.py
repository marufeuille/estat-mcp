from unittest.mock import MagicMock, patch

import pytest

import src.estat_client as client
from src.estat_client import EStatAPIError, get_meta_info, get_stats_data, get_stats_list


def _mock_response(json_data: dict, status_code: int = 200) -> MagicMock:
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = json_data
    mock.raise_for_status = MagicMock()
    return mock


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

API_ERROR_RESPONSE = {
    "GET_STATS_LIST": {
        "RESULT": {"STATUS": 100, "ERROR_MSG": "パラメータが不正です"},
        "PARAMETER": {},
    }
}


@patch("src.estat_client.httpx.Client")
def test_get_stats_list_success(mock_client_cls):
    mock_client_cls.return_value.__enter__.return_value.get.return_value = _mock_response(STATS_LIST_OK)
    result = get_stats_list(search_word="人口")
    assert "GET_STATS_LIST" in result


@patch("src.estat_client.httpx.Client")
def test_get_stats_data_success(mock_client_cls):
    mock_client_cls.return_value.__enter__.return_value.get.return_value = _mock_response(STATS_DATA_OK)
    result = get_stats_data("0003448237")
    assert "GET_STATS_DATA" in result


@patch("src.estat_client.httpx.Client")
def test_get_meta_info_success(mock_client_cls):
    mock_client_cls.return_value.__enter__.return_value.get.return_value = _mock_response(META_INFO_OK)
    result = get_meta_info("0003448237")
    assert "GET_META_INFO" in result


@patch("src.estat_client.httpx.Client")
def test_api_error_raises_estat_api_error(mock_client_cls):
    mock_client_cls.return_value.__enter__.return_value.get.return_value = _mock_response(API_ERROR_RESPONSE)
    with pytest.raises(EStatAPIError) as exc_info:
        get_stats_list()
    assert "100" in str(exc_info.value)


@patch("src.estat_client.httpx.Client")
def test_get_stats_list_sends_app_id(mock_client_cls):
    mock_get = mock_client_cls.return_value.__enter__.return_value.get
    mock_get.return_value = _mock_response(STATS_LIST_OK)
    get_stats_list()
    call_kwargs = mock_get.call_args
    params = call_kwargs.kwargs.get("params") or call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
    if not params:
        params = call_kwargs.kwargs.get("params", {})
    assert "appId" in params


def test_no_app_id_raises(monkeypatch):
    monkeypatch.setattr(client, "ESTAT_APP_ID", "")
    with pytest.raises(ValueError, match="ESTAT_APP_ID is not set"):
        get_stats_list()
