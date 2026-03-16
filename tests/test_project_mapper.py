"""
Tests for project_mapper.py.
"""

import sys
from pathlib import Path

from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from project_mapper import ProjectMapper, ProjectMapperConfig


@pytest.fixture
def projects():
    return [
        {
            "id": 1,
            "tenant_id": "t-001",
            "project_code": "PRJ-001",
            "project_name": "Bridge Repair",
            "aliases": "BR-001, Híd javítás",
            "reference_patterns": "Munkaszám BR-001",
            "is_active": 1,
        },
        {
            "id": 2,
            "tenant_id": "t-001",
            "project_code": "PRJ-002",
            "project_name": "Road Upgrade",
            "aliases": "RD-002",
            "reference_patterns": None,
            "is_active": 1,
        },
    ]


class TestProjectMapper:
    def test_direct_match_from_line_descriptions(self, projects):
        mapper = ProjectMapper()

        result = mapper.map_invoice_lines(
            ["Szolgáltatás a BR-001 munkaszámhoz"],
            projects,
        )

        assert result.matched is True
        assert result.project_id == 1
        assert result.matched_by == "direct_rules"

    def test_returns_unmatched_for_ambiguous_reference(self, projects):
        mapper = ProjectMapper()

        result = mapper.map_invoice_lines(
            ["Projekt költség elszámolás"],
            projects,
        )

        assert result.matched is False

    def test_validates_gemini_reference_against_tenant_projects(self, projects, monkeypatch):
        mapper = ProjectMapper()
        monkeypatch.setattr(mapper, "_extract_with_gemini", lambda lines, available: "RD-002")

        result = mapper.map_invoice_lines(
            ["Útépítési szolgáltatás belső hivatkozással"],
            projects,
        )

        assert result.matched is True
        assert result.project_id == 2
        assert result.matched_by == "gemini_validated"

    def test_gemini_non_unique_reference_stays_unmatched(self, projects, monkeypatch):
        mapper = ProjectMapper()
        monkeypatch.setattr(mapper, "_extract_with_gemini", lambda lines, available: "projekt")

        result = mapper.map_invoice_lines(
            ["Általános projektmunka"],
            projects,
        )

        assert result.matched is False
        assert result.extracted_reference == "projekt"

    def test_parses_reference_from_json_response(self):
        mapper = ProjectMapper()
        assert mapper._parse_reference_from_response('{"reference":"PRJ-001","reason":"exact"}') == "PRJ-001"

    def test_returns_unmatched_when_no_active_projects(self):
        mapper = ProjectMapper()
        result = mapper.map_invoice_lines(
            ["PRJ-001"],
            [{"id": 1, "project_code": "PRJ-001", "project_name": "Inactive", "is_active": 0}],
        )
        assert result.matched is False
        assert result.reason == "No active projects configured"

    def test_returns_unmatched_when_no_line_descriptions(self, projects):
        mapper = ProjectMapper()
        result = mapper.map_invoice_lines([], projects)
        assert result.matched is False
        assert result.reason == "No line descriptions available"

    def test_extract_with_gemini_parses_code_fenced_json(self, projects):
        mapper = ProjectMapper(ProjectMapperConfig(api_key="demo-key"))
        mapper.client = SimpleNamespace(
            models=SimpleNamespace(
                generate_content=lambda **kwargs: SimpleNamespace(
                    text='```json\n{"reference":"PRJ-001","reason":"exact"}\n```'
                )
            )
        )

        result = mapper.map_invoice_lines(
            ["Belső kivitelezés a híd projekthez"],
            projects,
        )

        assert result.matched is True
        assert result.project_id == 1
        assert result.to_dict()["matched_by"] == "gemini_validated"
