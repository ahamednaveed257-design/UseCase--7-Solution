from fastapi.testclient import TestClient

from Main import app


client = TestClient(app)


def test_review_article_has_pending_approval_and_scores():
    response = client.post(
        "/v1/articles/review",
        json={
            "articleContent": (
                "Prerequisite: Confirm network access. "
                "Validate: Confirm the test page opens. "
                "Rollback: Disconnect and restore the previous network."
            )
        },
        headers={"x-user-id": "test-user"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["approvalStatus"] == "PENDING_HUMAN_APPROVAL"
    assert set(body["scores"]) == {
        "stalenessScore",
        "ambiguityScore",
        "structureScore",
    }
    assert all(0 <= score <= 100 for score in body["scores"].values())


def test_missing_article_input_is_rejected():
    response = client.post("/v1/articles/review", json={})
    assert response.status_code == 422


def test_sensitive_article_input_is_rejected():
    response = client.post(
        "/v1/articles/review",
        json={"articleContent": "password=example-value"},
    )
    assert response.status_code == 422


def test_gap_analysis_has_no_meaningful_draft_without_resolution_evidence():
    response = client.post(
        "/v1/gaps/analyze",
        json={"theme": "Printer not responding"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["coverage"] == "NONE"
    assert body["priority"] == "HIGH"
    assert body["approvalStatus"] == "PENDING_HUMAN_APPROVAL"
    assert "[TO REVIEW]" in body["draftArticle"]["steps"][0]


def test_health_reports_publication_disabled():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["automaticPublishing"] == "disabled"


def test_architecture_design_returns_markdown_and_pending_status():
    response = client.post(
        "/v1/architecture/design",
        json={
            "purpose": "Govern knowledge article review and gap analysis.",
            "sources": ["Knowledge Repository"],
            "constraints": {"region": "Central India"},
            "approvedReferences": ["Microsoft Foundry approved pattern"],
        },
        headers={"x-user-role": "Knowledge Analyst"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "design_foundry_architecture"
    assert "```mermaid" in body["markdown"]
    assert body["approvalStatus"] == "PENDING_HUMAN_APPROVAL"


def test_reader_role_cannot_run_article_review():
    response = client.post(
        "/v1/articles/review",
        json={"articleContent": "Validate the test service. Rollback if the test fails."},
        headers={"x-user-role": "Reader"},
    )
    assert response.status_code == 403


def test_plain_text_upload_review_is_pending():
    response = client.post(
        "/v1/articles/upload",
        files={"file": ("article.md", b"Prerequisite: Test access. Validate: Confirm service. Rollback: Restore network.", "text/markdown")},
        headers={"x-user-role": "Knowledge Analyst"},
    )
    assert response.status_code == 200
    assert response.json()["approvalStatus"] == "PENDING_HUMAN_APPROVAL"
