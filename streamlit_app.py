import httpx
import streamlit as st

st.set_page_config(page_title="Knowledge Curator", page_icon="KC", layout="wide")
st.title("Knowledge Curator")
st.caption("All findings and drafts require PENDING_HUMAN_APPROVAL. Automatic publishing is disabled.")

api_url = st.sidebar.text_input("API base URL", value="http://127.0.0.1:8000")

tab_review, tab_gap, tab_architecture = st.tabs(
    ["Review Article", "Find Gaps", "Architecture Design"]
)

with tab_review:
    article_id = st.text_input("Article ID", placeholder="KB-001")
    article_content = st.text_area("Article content", height=220)
    if st.button("Review article", type="primary"):
        if not article_id and not article_content:
            st.error("Provide an Article ID or article content.")
        else:
            payload = {
                "articleId": article_id or None,
                "articleContent": article_content or None,
            }
            try:
                response = httpx.post(
                    f"{api_url}/v1/articles/review",
                    json=payload,
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
    if st.button("Analyze gaps"):
        if not theme:
            st.error("Ticket theme is required.")
        else:
            payload = {
                "theme": theme,
                "ticketThemes": [line.strip() for line in themes.splitlines() if line.strip()],
                "resolutionNotes": resolution_notes or None,
            }
            try:
                response = httpx.post(
                    f"{api_url}/v1/gaps/analyze",
                    json=payload,
                    timeout=30,
                )
                if response.is_success:
                    st.json(response.json())
                else:
                    st.error(response.text)
            except httpx.HTTPError as exc:
                st.error(f"Unable to reach the Knowledge Curator API: {exc}")
