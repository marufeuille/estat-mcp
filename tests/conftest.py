import pytest
import src.estat_client as client_module


@pytest.fixture(autouse=True)
def set_dummy_app_id(monkeypatch):
    monkeypatch.setattr(client_module, "ESTAT_APP_ID", "dummy_app_id_for_tests")
