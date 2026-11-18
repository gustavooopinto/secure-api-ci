import os

import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def setup_materials(tmp_path, monkeypatch):
    materials = tmp_path / "materials"
    (materials / "sub").mkdir(parents=True)
    (materials / "notes.txt").write_text("ALLOWED")
    (tmp_path / "secret.txt").write_text("TOP-SECRET")
    monkeypatch.setattr(api, "MATERIALS_DIR", materials)
    return materials


def assert_denied(response):
    assert 400 <= response.status_code < 500
    assert b"TOP-SECRET" not in response.data


# ---- permitted operation ----

def test_authenticated_user_can_download_material(client, tmp_path, monkeypatch):
    setup_materials(tmp_path, monkeypatch)
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 200
    assert response.data == b"ALLOWED"


# ---- forbidden operations (R1, R6, R7) ----

def test_unauthenticated_download_denied(client, tmp_path, monkeypatch):
    setup_materials(tmp_path, monkeypatch)
    response = client.get("/files", query_string={"path": "notes.txt"})
    assert response.status_code == 401


def test_dotdot_traversal_blocked(client, tmp_path, monkeypatch):
    setup_materials(tmp_path, monkeypatch)
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files", query_string={"path": "../secret.txt"}))


def test_absolute_path_blocked(client, tmp_path, monkeypatch):
    setup_materials(tmp_path, monkeypatch)
    login(client, "alice", "alicepw")
    outside = str(tmp_path / "secret.txt")
    assert_denied(client.get("/files", query_string={"path": outside}))


# ---- variations that challenge an incomplete patch ----

def test_nested_traversal_blocked(client, tmp_path, monkeypatch):
    # Passes a naive startswith("..") check: starts inside, escapes later.
    setup_materials(tmp_path, monkeypatch)
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files", query_string={"path": "sub/../../secret.txt"}))


def test_symlink_escape_blocked(client, tmp_path, monkeypatch):
    materials = setup_materials(tmp_path, monkeypatch)
    os.symlink(tmp_path / "secret.txt", materials / "link.txt")
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files", query_string={"path": "link.txt"}))


def test_missing_file_error_does_not_leak_internal_path(client, tmp_path, monkeypatch):
    setup_materials(tmp_path, monkeypatch)
    login(client, "alice", "alicepw")
    response = client.get("/files", query_string={"path": "nope.txt"})
    assert 400 <= response.status_code < 500
    assert str(tmp_path) not in response.get_data(as_text=True)