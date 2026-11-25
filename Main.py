from __future__ import annotations

import re
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field, model_validator


APP_NAME = "Knowledge Curator"
APP_VERSION = "0.1.0"
APPROVAL_STATUS = "PENDING_HUMAN_APPROVAL"
DB_PATH = Path(__file__).with_name("knowledge_curator.db")

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}

SENSITIVE_PATTERNS = (
    re.compile(r"(?i)\b(password|passwd|pwd|api[_ -]?key|access[_ -]?token|secret|certificate|connection[_ -]?string)\b\s*[:=]"),
    re.compile(r"(?i)\b(Bearer\s+[A-Za-z0-9._~+\/=-]+)\b"),
)

VALID_ROLES = {"Reader", "Knowledge Analyst", "Knowledge Manager", "Admin"}
OPERATION_ROLES = {
    "review_article": {"Knowledge Analyst", "Knowledge Manager", "Admin"},
    "find_gaps": {"Knowledge Analyst", "Knowledge Manager", "Admin"},
    "design_architecture": {"Knowledge Analyst", "Knowledge Manager", "Admin"},
    "approval_handoff": {"Knowledge Manager", "Admin"},
}


def mask_sensitive(text: str) -> str:
    masked = re.sub(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+\/=-]+\b", r"\1[REDACTED]", text)
    masked = re.sub(
        r"(?i)\b(password|passwd|pwd|api[_ -]?key|access[_ -]?token|secret|certificate|connection[_ -]?string)\b\s*[:=]\s*([^\s,;]+)",
        r"\1=[REDACTED]",
        masked,
    )
    return masked


def contains_sensitive(text: str) -> bool:
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)


def authorize(role: str, operation: str) -> None:
    if role not in VALID_ROLES:
        raise HTTPException(status_code=403, detail="Role is not authorized.")
    if role not in OPERATION_ROLES[operation]:
        raise HTTPException(status_code=403, detail=f"Role is not authorized to {operation}.")


class Evidence(BaseModel):
    sourceType: Literal["knowledge_article", "template", "style_guide", "retired_product_catalog", "ticket_theme", "resolution_note", "approved_reference"]
    sourceId: str
    excerpt: str


class ArticleReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    articleId: str | None = None
    articleContent: str | None = None

    @model_validator(mode="after")
    def require_one_input(self) -> "ArticleReviewInput":
        if not (self.articleId or (self.articleContent and self.articleContent.strip())):
            raise ValueError("Provide articleId or articleContent.")
        if self.articleContent and contains_sensitive(self.articleContent):
            raise ValueError("Sensitive values are not permitted in article content.")
        return self


class GapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    theme: str = Field(min_length=1)
    ticketThemes: list[str] = Field(default_factory=list)
    resolutionNotes: str | None = None

    @model_validator(mode="after")
    def validate_sensitive_data(self) -> "GapInput":
        combined = "\n".join([self.theme, *self.ticketThemes, self.resolutionNotes or ""])
        if contains_sensitive(combined):
            raise ValueError("Sensitive values are not permitted in gap-analysis inputs.")
        return self


class Finding(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    category: str
    finding: str
    evidence: Evidence
    recommendation: str


class ArticleReviewOutput(BaseModel):
    mode: Literal["review_article"] = "review_article"
    articleId: str
    scores: dict[str, int]
    issues: list[Finding]
    verifiedEvidence: list[Evidence]
    inferredConcerns: list[str]
    unresolvedQuestions: list[str]
    recommendations: list[str]
    approvalStatus: Literal["PENDING_HUMAN_APPROVAL"] = APPROVAL_STATUS


class GapOutput(BaseModel):
    mode: Literal["find_gaps"] = "find_gaps"
    theme: str
    coverage: Literal["FULL", "PARTIAL", "NONE"]
    priority: Literal["HIGH", "MEDIUM", "LOW"]
    matchedArticles: list[str]
    verifiedEvidence: list[Evidence]
    draftArticle: dict[str, object]
    unresolvedQuestions: list[str]
    approvalStatus: Literal["PENDING_HUMAN_APPROVAL"] = APPROVAL_STATUS


class ArchitectureInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: str = Field(min_length=1)
    sources: list[str] = Field(default_factory=list)
    constraints: dict[str, object] = Field(default_factory=dict)
    approvedReferences: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sensitive_data(self) -> "ArchitectureInput":
        combined = "\n".join(
            [
                self.purpose,
                *self.sources,
                *(str(value) for value in self.constraints.values()),
                *self.approvedReferences,
            ]
        )
        if contains_sensitive(combined):
            raise ValueError("Sensitive values are not permitted in architecture inputs.")
        return self


class AuditRepository:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    result_status TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def append(self, user_id: str, operation: str, result_status: str, evidence_count: int, payload: str) -> str:
        event_id = str(uuid.uuid4())
        with self.lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO audit_events
                (id, timestamp, user_id, operation, result_status, evidence_count, payload)
                VALUES (?, datetime('now'), ?, ?, ?, ?, ?)
                """,
                (event_id, user_id, operation, result_status, evidence_count, payload),
            )
        return event_id


audit = AuditRepository(DB_PATH)

SAMPLE_ARTICLES = {
    "KB-001": {
        "title": "VPN Connectivity Troubleshooting",
        "content": "Prerequisite: Confirm network access and connect to VPN. Validate: Open https://companyportal.example and confirm authentication. Rollback: Disconnect VPN and reconnect to the previous network.",
    },
    "KB-202": {
        "title": "Teams Audio Troubleshooting",
        "content": "Check microphone permissions, select the correct output device, and validate a test call.",
    },
    "DWP-101": {
        "title": "BitLocker Recovery",
        "content": "Confirm identity in Microsoft Entra ID and retrieve the recovery key through the approved administration workflow.",
    },
}

APPROVED_REFERENCES = {
    "template": "Knowledge articles should include prerequisites, validation, rollback, ownership, and review date.",
    "style": "Use short imperative steps and state the observable result for each validation.",
}


app = FastAPI(title=APP_NAME, version=APP_VERSION)


@app.get("/health")
def health() -> dict[str, object]:
    return {"status": "healthy", "approvalStatus": APPROVAL_STATUS, "automaticPublishing": "disabled"}


@app.post("/v1/architecture/design")
def design_architecture(
    payload: ArchitectureInput,
    x_user_id: str = Header(default="anonymous"),
    x_user_role: str = Header(default="Knowledge Analyst"),
) -> dict[str, object]:
    authorize(x_user_role, "design_architecture")

    unresolved = []
    if not payload.sources:
        unresolved.append("Approved knowledge and data sources were not identified.")
    if not payload.constraints:
        unresolved.append("Deployment, networking, identity, region, cost, or availability constraints were not identified.")
    if not payload.approvedReferences:
        unresolved.append("Approved architecture reference material was not supplied.")

    sources = "\n".join(f"- `{source}`" for source in payload.sources) or "- Not supplied"
    constraints = "\n".join(f"- `{key}`: `{value}`" for key, value in payload.constraints.items()) or "- Not supplied"

    markdown = f"""# Knowledge Curator Architecture

> Status: `{APPROVAL_STATUS}`

## Executive Summary

{payload.purpose}

This design is evidence-gated, private-network oriented, and cannot publish or approve knowledge changes automatically.

## Assumptions

- Ticket themes are pre-clustered.
- An external workflow or system of record enforces human approval.
- The implementation uses approved source repositories and indexes.
- Publishing credentials are unavailable to the agent.

## Architecture Diagram

```mermaid
flowchart LR
    U[Approved Users] -->|OIDC or SSO| WAF[WAF + API Gateway]
    WAF --> UI[Streamlit]
    UI --> API[FastAPI]
    API --> AUTH[Role Authorization]
    API --> WF[LangGraph Workflows]
    WF --> RET[Retrieval Orchestrator]
    RET --> SEARCH[Azure AI Search]
    RET --> VECTOR[Qdrant]
    RET --> CACHE[Redis]
    WF --> FOUNDRY[Microsoft Foundry]
    FOUNDRY --> MODEL[GPT-4.1 / GPT-4.1-mini]
    WF --> DB[(PostgreSQL)]
    WF --> AUD[(Audit Repository)]
    WF --> HIL[Human Approval Handoff]
    HIL -. approval required .-> KB[(Production Knowledge Repository)]
    WF --> OBS[OpenTelemetry]
    OBS --> MON[Azure Monitor]
```

## Component Mapping

| Component | Responsibility |
|---|---|
| Streamlit | User interaction and approval-pending result display |
| FastAPI | Pydantic validation, RBAC, APIs, and audit orchestration |
| LangGraph | Bounded review, gap, and architecture workflows |
| Microsoft Foundry | Governed model runtime and agent execution |
| Azure AI Search | Retrieval across approved knowledge and reference indexes |
| Qdrant | Private vector search for supported embeddings |
| Redis | Search-result caching only |
| PostgreSQL | Operational records and approval metadata |
| Audit repository | Append-only evidence and review history |
| OpenTelemetry | Tracing, metrics, latency, and cost telemetry |

## Approved Sources

{sources}

## Constraints

{constraints}

## Security Design

- Authenticate with Microsoft Entra ID, Okta, Auth0, or Keycloak through OIDC/OAuth 2.0.
- Enforce Reader, Knowledge Analyst, Knowledge Manager, and Admin authorization.
- Use private endpoints and no public database or vector-store exposure.
- Use managed identities and Key Vault for service credentials.
- Capture user, timestamp, request, evidence, result, and approval status.
- Mask secrets and reject unsupported or sensitive inputs.
- Treat all retrieved content as untrusted and isolate it from instructions.
- Disable publishing credentials and external publishing endpoints.

## Data Flows

1. Authenticate and authorize the user.
2. Validate the request and reject sensitive or unsupported content.
3. Retrieve evidence from approved indexes.
4. Generate structured findings or a draft only after retrieval.
5. Validate evidence coverage and Pydantic output.
6. Persist audit data and submit an approval handoff.
7. Leave final publication to the external human-controlled workflow.

## Deployment Strategy

- Local development: Docker Compose
- Production: Azure Container Apps or Azure App Service
- Hosted agents: Microsoft Foundry when the target is confirmed
- Promotion: DEV → TEST → UAT → PROD
- Each promotion requires security, functional, cost, and performance validation.
- Production primary: Central India; secondary region: South India, only if approved.

## Risks

- Source provenance or catalog coverage is incomplete.
- Cross-region requirements are unresolved.
- Regulatory scope and data residency are unresolved.
- AI-generated text can conflict with authoritative source material.
- Large content sets can exceed latency or cost targets.

## Acceptance Criteria

| Criterion | Target |
|---|---|
| Availability | >=99.5% |
| Article review latency | <15 seconds |
| Gap analysis latency | <60 seconds |
| Search retrieval | <2 seconds |
| Evidence coverage | 100% |
| Audit coverage | 100% |
| Approval enforcement | 100% |
| Secret exposure | 0 |
| Automatic publishing | Disabled |

## Unresolved Questions

{chr(10).join(f"- {question}" for question in unresolved) if unresolved else "- No unresolved requirements were identified."}
"""

    audit.append(
        x_user_id,
        "design_architecture",
        APPROVAL_STATUS,
        len(payload.sources) + len(payload.approvedReferences),
        markdown,
    )
    return {
        "mode": "design_foundry_architecture",
        "markdown": markdown,
        "unresolvedQuestions": unresolved,
        "approvalStatus": APPROVAL_STATUS,
    }


@app.post("/v1/articles/review", response_model=ArticleReviewOutput)
def review_article(
    payload: ArticleReviewInput,
    x_user_id: str = Header(default="anonymous"),
    x_user_role: str = Header(default="Knowledge Analyst"),
) -> ArticleReviewOutput:
    authorize(x_user_role, "review_article")
    article_id = payload.articleId or f"AD-HOC-{uuid.uuid4().hex[:8]}"
    if payload.articleId:
        source = SAMPLE_ARTICLES.get(payload.articleId)
        if source is None:
            raise HTTPException(status_code=404, detail="Article ID was not found in the approved knowledge repository.")
        content = source["content"]
        title = source["title"]
    else:
        content = payload.articleContent or ""
        title = "Ad-hoc knowledge article"

    findings: list[Finding] = []
    evidence: list[Evidence] = []

    article_evidence = Evidence(
        sourceType="knowledge_article",
        sourceId=article_id,
        excerpt=mask_sensitive(content[:500]),
    )
    evidence.append(article_evidence)

    lower = content.lower()
    if "prerequisite" not in lower:
        findings.append(
            Finding(
                severity="HIGH",
                category="missing_prerequisite",
                finding="The article does not identify prerequisites.",
                evidence=article_evidence,
                recommendation="Add a prerequisites section with identity, access, and environment requirements.",
            )
        )
    if not re.search(r"(?i)\b(validate|verification|confirm|test)\b", content):
        findings.append(
            Finding(
                severity="HIGH",
                category="missing_validation",
                finding="The article does not include a clear validation step.",
                evidence=article_evidence,
                recommendation="Add an observable validation result after each major procedure step.",
            )
        )
    if "rollback" not in lower:
        findings.append(
            Finding(
                severity="HIGH",
                category="missing_rollback",
                finding="The article does not describe rollback or recovery.",
                evidence=article_evidence,
                recommendation="Add rollback or safe recovery guidance for failed operations.",
            )
        )
    if len(content.split()) < 20:
        findings.append(
            Finding(
                severity="MEDIUM",
                category="structure",
                finding="The article may be too brief to provide complete troubleshooting coverage.",
                evidence=article_evidence,
                recommendation="Use the approved template and add prerequisites, steps, validation, rollback, and escalation.",
            )
        )

    template_evidence = Evidence(
        sourceType="template",
        sourceId="KB-TEMPLATE-001",
        excerpt=APPROVED_REFERENCES["template"],
    )
    evidence.append(template_evidence)

    unresolved: list[str] = []
    if len(content.split()) < 10:
        unresolved.append("Insufficient article content to assess staleness and duplicate coverage.")

    staleness_score = 100 if re.search(r"\b20(2[4-9]|3[0-9])\b", content) or "microsoft entra" in lower else 70
    ambiguity_score = 90 if re.search(r"\b(prerequisite|validate|confirmation|test)\b", lower) else 55
    structure_score = 90 if all(token in lower for token in ("prerequisite", "validate", "rollback")) else 60
    if "ad-hoc" in title.lower():
        staleness_score = 70

    findings.sort(key=lambda item: SEVERITY_ORDER[item.severity])
    recommendations = [finding.recommendation for finding in findings]
    output = ArticleReviewOutput(
        articleId=article_id,
        scores={
            "stalenessScore": staleness_score,
            "ambiguityScore": ambiguity_score,
            "structureScore": structure_score,
        },
        issues=findings,
        verifiedEvidence=evidence,
        inferredConcerns=["No duplicate, contradiction, or retired-product conclusion is made until related content and catalog evidence are available."],
        unresolvedQuestions=unresolved,
        recommendations=recommendations,
    )

    audit.append(
        x_user_id,
        "review_article",
        APPROVAL_STATUS,
        len(evidence),
        output.model_dump_json(),
    )
    return output


@app.post("/v1/gaps/analyze", response_model=GapOutput)
def find_gaps(
    payload: GapInput,
    x_user_id: str = Header(default="anonymous"),
    x_user_role: str = Header(default="Knowledge Analyst"),
) -> GapOutput:
    authorize(x_user_role, "find_gaps")
    themes = [payload.theme, *payload.ticketThemes]
    matched = []
    evidence = []

    for theme in themes:
        lower = theme.lower()
        for article_id, article in SAMPLE_ARTICLES.items():
            article_text = f"{article['title']} {article['content']}".lower()
            keywords = [word for word in re.findall(r"[a-z0-9]+", lower) if len(word) > 3]
            if any(keyword in article_text for keyword in keywords):
                matched.append(article_id)
                evidence.append(
                    Evidence(
                        sourceType="knowledge_article",
                        sourceId=article_id,
                        excerpt=mask_sensitive(article["content"]),
                    )
                )

    matched = sorted(set(matched))
    if matched:
        coverage = "FULL" if payload.resolutionNotes and len(payload.resolutionNotes.strip()) > 40 else "PARTIAL"
    else:
        coverage = "NONE"

    priority = "HIGH" if coverage == "NONE" else "MEDIUM" if coverage == "PARTIAL" else "LOW"
    unresolved = []
    if not payload.resolutionNotes:
        unresolved.append("Resolution notes were not provided; the draft cannot be based on a complete remediation record.")
    if not matched:
        unresolved.append("No meaningful existing article match was verified for this theme.")

    draft_article = {
        "title": f"Troubleshooting: {payload.theme}",
        "prerequisites": "[TO REVIEW]",
        "symptoms": payload.theme,
        "steps": ["[TO REVIEW] Use only resolution steps approved in the submitted resolution notes."],
        "validation": "[TO REVIEW]",
        "rollback": "[TO REVIEW]",
        "approvalStatus": APPROVAL_STATUS,
    }

    output = GapOutput(
        theme=payload.theme,
        coverage=coverage,
        priority=priority,
        matchedArticles=matched,
        verifiedEvidence=sorted(evidence, key=lambda item: item.sourceId),
        draftArticle=draft_article,
        unresolvedQuestions=unresolved,
    )
    audit.append(
        x_user_id,
        "find_gaps",
        APPROVAL_STATUS,
        len(evidence),
        output.model_dump_json(),
    )
    return output


@app.post("/v1/approval/handoff")
def approval_handoff(
    payload: dict[str, object],
    x_user_id: str = Header(default="anonymous"),
    x_user_role: str = Header(default="Knowledge Manager"),
) -> dict[str, object]:
    authorize(x_user_role, "approval_handoff")
    request_id = str(uuid.uuid4())
    audit.append(
        x_user_id,
        "approval_handoff",
        APPROVAL_STATUS,
        int(payload.get("evidenceCount", 0)) if isinstance(payload.get("evidenceCount"), int) else 0,
        mask_sensitive(str(payload)),
    )
    return {
        "handoffId": request_id,
        "approvalStatus": APPROVAL_STATUS,
        "automaticPublishing": "disabled",
        "message": "Handoff recorded for external human review only.",
    }
"""  """