"""
Tenant-scoped project mapping for invoice line descriptions.

Uses deterministic matching first and Gemini as a best-effort extractor when
available. Failures never block the main reconciliation pipeline.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from invoice_agent import GENAI_AVAILABLE, InputSanitizer, genai

logger = logging.getLogger(__name__)


@dataclass
class ProjectMapperConfig:
    """Configuration for Gemini-backed project extraction."""
    api_key: str
    model_name: str = "gemini-1.5-flash"
    temperature: float = 0.1
    max_output_tokens: int = 200


@dataclass
class ProjectCandidate:
    """A normalized candidate string tied to a tenant project."""
    project_id: int
    project_code: str
    project_name: str
    candidate_text: str
    candidate_type: str


@dataclass
class ProjectMatchResult:
    """Result of a mapping attempt."""
    matched: bool
    project_id: Optional[int] = None
    project_code: Optional[str] = None
    project_name: Optional[str] = None
    extracted_reference: Optional[str] = None
    matched_by: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "project_id": self.project_id,
            "project_code": self.project_code,
            "project_name": self.project_name,
            "extracted_reference": self.extracted_reference,
            "matched_by": self.matched_by,
            "reason": self.reason,
        }


class ProjectMapper:
    """Resolve invoice line descriptions to tenant projects."""

    def __init__(self, config: Optional[ProjectMapperConfig] = None):
        self.config = config
        self.sanitizer = InputSanitizer()
        self.client = None

        if config and GENAI_AVAILABLE:
            self.client = genai.Client(api_key=config.api_key)

    @staticmethod
    def _normalize(value: str) -> str:
        value = value or ""
        return re.sub(r"[^a-z0-9]+", "", value.lower())

    @staticmethod
    def _split_candidate_values(value: Optional[str]) -> List[str]:
        if not value:
            return []
        parts = re.split(r"[,\n;|]+", value)
        return [part.strip() for part in parts if part.strip()]

    def _build_candidates(self, projects: List[Dict[str, Any]]) -> List[ProjectCandidate]:
        candidates: List[ProjectCandidate] = []
        for project in projects:
            project_id = int(project["id"])
            project_code = project["project_code"]
            project_name = project["project_name"]

            candidates.append(
                ProjectCandidate(project_id, project_code, project_name, project_code, "code")
            )
            candidates.append(
                ProjectCandidate(project_id, project_code, project_name, project_name, "name")
            )

            for alias in self._split_candidate_values(project.get("aliases")):
                candidates.append(
                    ProjectCandidate(project_id, project_code, project_name, alias, "alias")
                )
            for pattern in self._split_candidate_values(project.get("reference_patterns")):
                candidates.append(
                    ProjectCandidate(project_id, project_code, project_name, pattern, "pattern")
                )

        return candidates

    def _match_reference(
        self,
        reference: str,
        candidates: List[ProjectCandidate],
    ) -> Optional[ProjectCandidate]:
        normalized_reference = self._normalize(reference)
        if not normalized_reference:
            return None

        exact_matches = [
            candidate
            for candidate in candidates
            if self._normalize(candidate.candidate_text) == normalized_reference
        ]
        if len({match.project_id for match in exact_matches}) == 1 and exact_matches:
            return exact_matches[0]

        fuzzy_matches = [
            candidate
            for candidate in candidates
            if normalized_reference in self._normalize(candidate.candidate_text)
            or self._normalize(candidate.candidate_text) in normalized_reference
        ]
        unique_project_ids = {match.project_id for match in fuzzy_matches}
        if len(unique_project_ids) == 1 and fuzzy_matches:
            return fuzzy_matches[0]

        return None

    def _match_from_lines(
        self,
        line_descriptions: List[str],
        candidates: List[ProjectCandidate],
    ) -> Optional[ProjectCandidate]:
        for line in line_descriptions:
            match = self._match_reference(line, candidates)
            if match is not None:
                return match
        return None

    def _extract_with_gemini(
        self,
        line_descriptions: List[str],
        projects: List[Dict[str, Any]],
    ) -> Optional[str]:
        if self.client is None or self.config is None:
            return None

        safe_lines = [
            self.sanitizer.sanitize(line, "notes")
            for line in line_descriptions
            if line.strip()
        ]
        if not safe_lines:
            return None

        project_summary = "\n".join(
            f"- {project['project_code']}: {project['project_name']}"
            for project in projects
        )
        prompt = (
            "A következő számlasor leírásokból azonosítsd a projekt vagy munkaszám "
            "hivatkozást. Csak a projekt azonosítót vagy munkaszámot keresd, ne találj ki újat.\n\n"
            "Elérhető projektek:\n"
            f"{project_summary}\n\n"
            "Számlasor leírások:\n"
            + "\n".join(f"- {line}" for line in safe_lines)
            + "\n\nVálaszolj JSON formátumban: "
            '{"reference": "<azonosító vagy null>", "reason": "<rövid indoklás>"}'
        )

        try:
            response = self.client.models.generate_content(
                model=self.config.model_name,
                contents=prompt,
                config={
                    "temperature": self.config.temperature,
                    "max_output_tokens": self.config.max_output_tokens,
                },
            )
        except Exception as exc:
            logger.warning("Gemini project extraction failed: %s", exc)
            return None

        return self._parse_reference_from_response(response.text if response else "")

    def _parse_reference_from_response(self, response_text: str) -> Optional[str]:
        if not response_text:
            return None

        text = response_text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.DOTALL).strip()

        try:
            payload = json.loads(text)
            reference = payload.get("reference")
            if isinstance(reference, str) and reference.strip():
                return reference.strip()
            return None
        except json.JSONDecodeError:
            pass

        match = re.search(r'"reference"\s*:\s*"([^"]+)"', text)
        if match:
            return match.group(1).strip()

        if text.lower() in {"null", "none", "nincs", "ismeretlen"}:
            return None

        return text[:100].strip() or None

    def map_invoice_lines(
        self,
        line_descriptions: List[str],
        projects: List[Dict[str, Any]],
    ) -> ProjectMatchResult:
        """Map line descriptions to a tenant project."""
        active_projects = [project for project in projects if project.get("is_active", 1)]
        if not active_projects:
            return ProjectMatchResult(matched=False, reason="No active projects configured")

        clean_lines = [line.strip() for line in line_descriptions if line and line.strip()]
        if not clean_lines:
            return ProjectMatchResult(matched=False, reason="No line descriptions available")

        candidates = self._build_candidates(active_projects)
        direct_match = self._match_from_lines(clean_lines, candidates)
        if direct_match is not None:
            return ProjectMatchResult(
                matched=True,
                project_id=direct_match.project_id,
                project_code=direct_match.project_code,
                project_name=direct_match.project_name,
                extracted_reference=direct_match.candidate_text,
                matched_by="direct_rules",
                reason=f"Matched from {direct_match.candidate_type}",
            )

        extracted_reference = self._extract_with_gemini(clean_lines, active_projects)
        if not extracted_reference:
            return ProjectMatchResult(matched=False, reason="No project reference extracted")

        candidate = self._match_reference(extracted_reference, candidates)
        if candidate is None:
            return ProjectMatchResult(
                matched=False,
                extracted_reference=extracted_reference,
                reason="Extracted reference did not match a unique tenant project",
            )

        return ProjectMatchResult(
            matched=True,
            project_id=candidate.project_id,
            project_code=candidate.project_code,
            project_name=candidate.project_name,
            extracted_reference=extracted_reference,
            matched_by="gemini_validated",
            reason=f"Matched from {candidate.candidate_type}",
        )
