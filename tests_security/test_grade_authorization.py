import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def grade_of(student_id, course_id):
    row = api.find_grade(student_id, course_id)
    return None if row is None else row["grade"]


# ---- permitted operations (must keep working) ----

def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


def test_admin_can_update_any_grade(client):
    login(client, "admin1", "adminpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 19},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SSD")["grade"] == 19


# ---- forbidden operations (R1, R3, R4, R7) ----

def test_unauthenticated_update_denied_and_unchanged(client):
    before = grade_of(1001, "SRS")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 401
    assert grade_of(1001, "SRS") == before


def test_student_cannot_update_own_grade(client):
    login(client, "alice", "alicepw")
    before = grade_of(1001, "SRS")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 403
    assert grade_of(1001, "SRS") == before


def test_student_cannot_update_another_student(client):
    login(client, "alice", "alicepw")
    before = grade_of(1002, "SRS")
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SRS", "grade": 0},
    )
    assert response.status_code == 403
    assert grade_of(1002, "SRS") == before


def test_professor_cannot_update_unassigned_course(client):
    login(client, "prof_srs", "profpw")
    before = grade_of(1001, "SSD")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 20},
    )
    assert response.status_code == 403
    assert grade_of(1001, "SSD") == before


# ---- variations that challenge an incomplete patch ----

def test_professor_cannot_create_row_in_unassigned_course(client):
    # No (1002, SSD) row exists: a patch that only protects existing rows fails here.
    login(client, "prof_srs", "profpw")
    count = len(api.GRADES)
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SSD", "grade": 20},
    )
    assert response.status_code == 403
    assert len(api.GRADES) == count
    assert api.find_grade(1002, "SSD") is None


def test_update_denied_after_logout(client):
    login(client, "prof_srs", "profpw")
    client.post("/logout")
    before = grade_of(1001, "SRS")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 401
    assert grade_of(1001, "SRS") == before