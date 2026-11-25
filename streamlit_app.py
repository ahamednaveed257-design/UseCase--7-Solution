import os

import httpx
import streamlit as st

st.set_page_config(page_title="Knowledge Curator", page_icon="KC", layout="wide")
st.title("Knowledge Curator")
st.caption("All findings and drafts require PENDING_HUMAN_APPROVAL. Automatic publishing is disabled.")

api_url = st.sidebar.text_input("API base URL", value=os.getenv("KC_API_URL", "http://127.0.0.1:8000"))
role = st.sidebar.selectbox(
    "Local development role",
    ["Reader", "Knowledge Analyst", "Knowledge Manager", "Admin"],
)
bearer_token = st.sidebar.text_input("Bearer token (non-development)", type="password")
request_headers = {"x-user-role": role}
if bearer_token:
    request_headers["Authorization"] = f"Bearer {bearer_token}"

tab_review, tab_gap, tab_architecture = st.tabs(
    ["Review Article", "Find Gaps", "Architecture Design"]
)

with tab_review:
    article_id = st.text_input("Article ID", placeholder="KB-001")
    article_content = st.text_area("Article content", height=220)
    uploaded_article = st.file_uploader(
        "Or upload article",
        type=["txt", "md", "docx", "pdf", "json", "csv", "xml", "yaml", "yml", "html"],
    )
    if st.button("Review article", type="primary"):
        if not article_id and not article_content and uploaded_article is None:
            st.error("Provide an Article ID, article content, or article file.")
        else:
            try:
                if uploaded_article is not None:
                    response = httpx.post(
                        f"{api_url}/v1/articles/upload",
                        files={
                            "file": (
                                uploaded_article.name,
                                uploaded_article.getvalue(),
                                uploaded_article.type,
                            )
                        },
                        headers=request_headers,
                        timeout=30,
                    )
                else:
                    payload = {
                        "articleId": article_id or None,
                        "articleContent": article_content or None,
                    }
                    response = httpx.post(
                        f"{api_url}/v1/articles/review",
                        json=payload,
                        headers=request_headers,
                        timeout=30,
                    )
                if response.is_success:
                    st.json(response.json())
                else:
                    st.error(response.text)
            except httpx.HTTPError as exc:
                st.error(f"Unable to reach the Knowledge Curator API: {exc}")

with tab_architecture:
    purpose = st.text_area("Solution purpose")
    sources = st.text_area("Approved sources (one per line)")
    constraints = st.text_area("Approved constraints (one key/value per line)")
    references = st.text_area("Approved architecture references (one per line)")
    if st.button("Design architecture"):
        if not purpose:
            st.error("Purpose is required.")
        else:
            constraint_map = {}
            for line in constraints.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    constraint_map[key.strip()] = value.strip()
            payload = {
                "purpose": purpose,
                "sources": [line.strip() for line in sources.splitlines() if line.strip()],
                "constraints": constraint_map,
                "approvedReferences": [
                    line.strip() for line in references.splitlines() if line.strip()
                ],
            }
            try:
                response = httpx.post(
                    f"{api_url}/v1/architecture/design",
                    json=payload,
                    headers=request_headers,
                    timeout=30,
                )
                if response.is_success:
                    result = response.json()
                    st.markdown(result["markdown"])
                else:
                    st.error(response.text)
            except httpx.HTTPError as exc:
                st.error(f"Unable to reach the Knowledge Curator API: {exc}")

with tab_gap:
    theme = st.text_input("Ticket theme")
    themes = st.text_area("Additional pre-clustered themes (one per line)")
    resolution_notes = st.text_area("Resolution notes", height=220)
    impact_option = st.selectbox(
        "Significant impact",
        ["Unknown", "Yes", "No"],
        help="HIGH priority for NONE coverage requires evidence of significant impact.",
    )
    if st.button("Analyze gaps"):
        if not theme:
            st.error("Ticket theme is required.")
        else:
            payload = {
                "theme": theme,
                "ticketThemes": [line.strip() for line in themes.splitlines() if line.strip()],
                "resolutionNotes": resolution_notes or None,
            }
            if impact_option != "Unknown":
                payload["significantImpact"] = impact_option == "Yes"
            try:
                response = httpx.post(
                    f"{api_url}/v1/gaps/analyze",
                    json=payload,
                    headers=request_headers,
                    timeout=30,
                )
                if response.is_success:
                    st.json(response.json())
                else:
                    st.error(response.text)
            except httpx.HTTPError as exc:
                st.error(f"Unable to reach the Knowledge Curator API: {exc}")
