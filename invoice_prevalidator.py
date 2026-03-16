"""
Reusable invoice pre-validation for NAV XML payloads.

This module keeps XML rule evaluation separate from the transport-oriented
`NavClient` implementation so the same rules can be reused for outbound
pre-submit validation and inbound reconciliation checks.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from lxml import etree  # type: ignore[import-untyped]

from nav_client import NAMESPACES, NavErrorCode

logger = logging.getLogger(__name__)


class ValidationSeverity(str, Enum):
    """Severity for pre-validation findings."""

    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ValidationWarning:
    """Structured local validation finding."""

    code: str
    message: str
    pointer: str = ""
    severity: ValidationSeverity = ValidationSeverity.WARNING
    is_blocking: bool = False

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


class InvoicePreValidator:
    """Evaluate XML rules that can be inferred locally before NAV rejects them."""

    def __init__(self, namespaces: Optional[Dict[str, str]] = None):
        self.namespaces = namespaces or NAMESPACES
        self.rule_catalog = self._build_rule_catalog()

    def validate_sept_2025_rules(
        self,
        invoice_xml: bytes,
    ) -> List[ValidationWarning]:
        """Validate decoded invoice XML bytes and return structured findings."""
        findings: List[ValidationWarning] = []

        try:
            root = etree.fromstring(invoice_xml)
        except etree.XMLSyntaxError as exc:
            logger.warning("Could not parse invoice XML for validation: %s", exc)
            return findings

        ns = self.namespaces.get("data", "")

        self._validate_completion_date_range(root, ns, findings)
        self._validate_reverse_charge_buyer(root, ns, findings)
        self._validate_modification_number(root, ns, findings)
        self._validate_modification_sequence(root, ns, findings)
        self._validate_exchange_rate(root, ns, findings)
        self._validate_vat_group_consistency(root, ns, findings)
        self._validate_vat_summary_and_lines(root, ns, findings)

        return findings

    @staticmethod
    def format_findings(
        findings: Iterable[ValidationWarning],
    ) -> List[str]:
        """Return backward-compatible string messages used by older callers/tests."""
        return [f"[{finding.code}] {finding.message}" for finding in findings]

    def _build_rule_catalog(self) -> Dict[str, Dict[str, Any]]:
        """Metadata for known validation codes, even when some are NAV-only."""
        codes = [
            NavErrorCode.VAT_RATE_MISMATCH,
            NavErrorCode.VAT_SUMMARY_MISMATCH,
            NavErrorCode.VAT_LINE_ITEM_ERROR,
            NavErrorCode.INVALID_COMPLETION_DATE_RANGE,
            NavErrorCode.MISSING_UNIT_OF_MEASURE_OWN,
            NavErrorCode.MODIFICATION_NUMBER_SAME_AS_ORIGINAL,
            NavErrorCode.INCORRECT_VAT_MARKING_581,
            NavErrorCode.INCORRECT_VAT_MARKING_582,
            NavErrorCode.INCORRECT_VAT_MARKING_583,
            NavErrorCode.INCORRECT_VAT_MARKING_584,
            NavErrorCode.VAT_DATA_WITH_EXEMPTION,
            NavErrorCode.VAT_DATA_OUT_OF_SCOPE,
            NavErrorCode.DOMESTIC_REVERSE_CHARGE_BUYER,
            NavErrorCode.MISSING_PERFORMANCE_DATE_AGGREGATE,
            NavErrorCode.VAT_SUMMARY_OUT_OF_SCOPE,
            NavErrorCode.UNREALISTIC_MODIFICATION_SEQUENCE,
            NavErrorCode.EXCHANGE_RATE_MISMATCH,
            NavErrorCode.EXTREME_EXCHANGE_RATE,
            NavErrorCode.INVALID_BUYER_VAT_GROUP,
            NavErrorCode.TAX_NUMBER_VAT_GROUP_ISSUE,
            NavErrorCode.MODIFY_CANCELLED_INVOICE,
        ]
        return {
            code.value: {
                "code": code.value,
                "severity": (
                    ValidationSeverity.ERROR.value
                    if code.is_sept_2025_blocking
                    else ValidationSeverity.WARNING.value
                ),
                "is_blocking": code.is_sept_2025_blocking,
            }
            for code in codes
        }

    def _add_finding(
        self,
        findings: List[ValidationWarning],
        code: NavErrorCode,
        message: str,
        pointer: str = "",
    ) -> None:
        findings.append(
            ValidationWarning(
                code=code.value,
                message=message,
                pointer=pointer,
                severity=(
                    ValidationSeverity.ERROR
                    if code.is_sept_2025_blocking
                    else ValidationSeverity.WARNING
                ),
                is_blocking=code.is_sept_2025_blocking,
            )
        )

    def _validate_completion_date_range(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """[330] Performance period end date must not precede start date."""
        for line_elem in self._findall(root, ns, "line"):
            date_from_str = self._find_text(line_elem, ns, "lineDeliveryDate")
            date_to_str = self._find_text(line_elem, ns, "lineDeliveryDateTo")
            if date_from_str and date_to_str and date_to_str < date_from_str:
                line_number = (
                    self._find_text(line_elem, ns, "lineNumber") or "?"
                )
                self._add_finding(
                    findings,
                    NavErrorCode.INVALID_COMPLETION_DATE_RANGE,
                    (
                        f"Line {line_number}: performance period end "
                        f"({date_to_str}) precedes start ({date_from_str})"
                    ),
                    pointer=f"line[{line_number}].lineDeliveryDateTo",
                )

    def _validate_reverse_charge_buyer(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """
        [596] Domestic reverse charge requires buyer to be domestic VAT taxpayer.
        """
        exemption_case = self._find_text_recursive(root, ns, "vatExemptionCase")
        if not exemption_case:
            return

        is_reverse_charge = exemption_case in ("AAM", "DOMESTIC_REVERSE_CHARGE")
        if not is_reverse_charge:
            return

        buyer_vat_code = self._find_text_by_paths(
            root,
            [
                self._path(ns, "customerTaxNumber", "vatCode"),
                ".//customerTaxNumber/vatCode",
            ],
        )
        buyer_taxpayer_id = self._find_text_by_paths(
            root,
            [
                self._path(ns, "customerTaxNumber", "taxpayerId"),
                ".//customerTaxNumber/taxpayerId",
            ],
        )

        if not buyer_taxpayer_id:
            self._add_finding(
                findings,
                NavErrorCode.DOMESTIC_REVERSE_CHARGE_BUYER,
                "Domestic reverse charge but buyer has no tax number",
                pointer="customerTaxNumber/taxpayerId",
            )
        elif buyer_vat_code and buyer_vat_code != "2":
            self._add_finding(
                findings,
                NavErrorCode.DOMESTIC_REVERSE_CHARGE_BUYER,
                (
                    f"Domestic reverse charge but buyer vatCode={buyer_vat_code} "
                    "expected '2' for domestic VAT taxpayer"
                ),
                pointer="customerTaxNumber/vatCode",
            )

    def _validate_modification_number(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """[560] Modification invoice number must differ from original."""
        invoice_number = self._find_text_recursive(root, ns, "invoiceNumber")
        original_invoice_number = self._find_text_recursive(
            root,
            ns,
            "originalInvoiceNumber",
        )
        if (
            invoice_number
            and original_invoice_number
            and invoice_number == original_invoice_number
        ):
            self._add_finding(
                findings,
                NavErrorCode.MODIFICATION_NUMBER_SAME_AS_ORIGINAL,
                (
                    f"Modification invoice number '{invoice_number}' is "
                    "identical to original invoice number"
                ),
                pointer="modificationReference/originalInvoiceNumber",
            )

    def _validate_modification_sequence(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """[1150] Sanity-check modification sequence values when present."""
        original_invoice_number = self._find_text_recursive(
            root,
            ns,
            "originalInvoiceNumber",
        )
        if not original_invoice_number:
            return

        modification_index_raw = self._find_text_recursive(root, ns, "modificationIndex")
        if not modification_index_raw:
            return

        try:
            modification_index = int(modification_index_raw)
        except ValueError:
            return

        if modification_index <= 0:
            self._add_finding(
                findings,
                NavErrorCode.UNREALISTIC_MODIFICATION_SEQUENCE,
                (
                    "Modification sequence must be a positive integer when "
                    f"referencing original invoice '{original_invoice_number}'"
                ),
                pointer="modificationIndex",
            )

    def _validate_exchange_rate(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """
        [1300/1310] Exchange rate sanity checks for foreign-currency invoices.
        """
        currency = self._find_text_recursive(root, ns, "currencyCode")
        if not currency or currency == "HUF":
            return

        rate_str = self._find_text_recursive(root, ns, "exchangeRate")
        if not rate_str:
            return

        try:
            rate = float(rate_str)
        except (ValueError, TypeError):
            return

        net_huf_str = self._find_text_recursive(
            root,
            ns,
            "invoiceNetAmountHUF",
        )
        net_str = self._find_text_recursive(root, ns, "invoiceNetAmount")

        if net_huf_str and net_str:
            try:
                net_huf = float(net_huf_str)
                net = float(net_str)
                if net > 0:
                    implied_rate = net_huf / net
                    if abs(implied_rate - rate) > rate * 0.1:
                        self._add_finding(
                            findings,
                            NavErrorCode.EXCHANGE_RATE_MISMATCH,
                            (
                                f"Exchange rate {rate} does not match "
                                "HUF/foreign ratio "
                                f"{implied_rate:.4f} (net_HUF={net_huf:.2f}, net={net:.2f})"
                            ),
                            pointer="exchangeRate",
                        )
            except (ValueError, TypeError, ZeroDivisionError):
                pass

        if rate <= 0.1 or rate > 100_000:
            self._add_finding(
                findings,
                NavErrorCode.EXTREME_EXCHANGE_RATE,
                f"Extreme exchange rate value: {rate} for {currency}",
                pointer="exchangeRate",
            )

    def _validate_vat_group_consistency(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """
        [435]/[82]/[91] Conservative tax-number vs VAT-treatment
        consistency checks.

        These checks are intentionally heuristic. They surface likely issues
        without
        claiming parity with NAV's full server-side validation matrix.
        """
        vat_rates = self._collect_vat_rates(root, ns)
        has_taxable_vat = any(rate > 0 for rate in vat_rates)
        if not has_taxable_vat:
            return

        buyer_taxpayer_id = self._find_text_by_paths(
            root,
            [
                self._path(ns, "customerTaxNumber", "taxpayerId"),
                ".//customerTaxNumber/taxpayerId",
            ],
        )
        buyer_vat_code = self._find_text_by_paths(
            root,
            [
                self._path(ns, "customerTaxNumber", "vatCode"),
                ".//customerTaxNumber/vatCode",
            ],
        )

        if buyer_taxpayer_id and not buyer_vat_code:
            self._add_finding(
                findings,
                NavErrorCode.TAX_NUMBER_VAT_GROUP_ISSUE,
                (
                    "Buyer tax number is present but VAT group code is missing while "
                    "taxable VAT rates are reported"
                ),
                pointer="customerTaxNumber/vatCode",
            )
            return

        if buyer_vat_code and buyer_vat_code not in {"1", "2", "3", "4", "5"}:
            self._add_finding(
                findings,
                NavErrorCode.INVALID_BUYER_VAT_GROUP,
                (
                    f"Buyer vatCode '{buyer_vat_code}' is not a recognized "
                    "VAT group"
                ),
                pointer="customerTaxNumber/vatCode",
            )
            return

        if buyer_vat_code and buyer_vat_code != "2":
            rates_str = ", ".join(f"{rate:g}%" for rate in sorted(vat_rates))
            self._add_finding(
                findings,
                NavErrorCode.VAT_RATE_MISMATCH,
                (
                    f"Taxable VAT rates ({rates_str}) are inconsistent with buyer "
                    f"vatCode={buyer_vat_code}"
                ),
                pointer="customerTaxNumber/vatCode",
            )

    def _validate_vat_summary_and_lines(
        self, root: etree._Element, ns: str, findings: List[ValidationWarning]
    ) -> None:
        """
        [734] VAT summary vs line items and [1311] per-line VAT calculation.
        """
        vat_summary_total = 0.0
        line_item_vat_total = 0.0

        for vat_rate_elem in self._findall(root, ns, "summaryByVatRate"):
            vat_amount = self._find_text_recursive(
                vat_rate_elem,
                ns,
                "vatRateVatAmount",
            )
            if vat_amount:
                try:
                    vat_summary_total += float(vat_amount)
                except ValueError:
                    pass

        for line_elem in self._findall(root, ns, "line"):
            line_item_vat_total += self._validate_line_item(
                line_elem,
                ns,
                findings,
            )

        if vat_summary_total > 0 and line_item_vat_total > 0:
            difference = abs(vat_summary_total - line_item_vat_total)
            if difference > 1.0:
                self._add_finding(
                    findings,
                    NavErrorCode.VAT_SUMMARY_MISMATCH,
                    (
                        "VAT summary mismatch: line items total "
                        f"{line_item_vat_total:.2f}, "
                        f"summary shows {vat_summary_total:.2f} (diff: {difference:.2f} HUF)"
                    ),
                    pointer="invoiceSummary",
                )

    def _validate_line_item(
        self,
        line_elem: etree._Element,
        ns: str,
        findings: List[ValidationWarning],
    ) -> float:
        """
        Validate a single line item's VAT calculation and return its VAT amount.
        """
        vat_amount = 0.0

        try:
            net_amount_str = self._find_text_by_paths(
                line_elem,
                [
                    self._path(ns, "lineNetAmount"),
                    ".//lineNetAmount",
                    self._path(ns, "lineNetAmountData", "lineNetAmount"),
                ],
                default="0",
            )
            vat_amount_str = self._find_text_by_paths(
                line_elem,
                [
                    self._path(ns, "lineVatAmount"),
                    ".//lineVatAmount",
                    self._path(ns, "lineVatData", "lineVatAmount"),
                ],
                default="0",
            )
            vat_rate_str = self._find_text_by_paths(
                line_elem,
                [self._path(ns, "vatPercentage"), ".//vatPercentage"],
                default="0",
            )

            net_amount = float(net_amount_str)
            vat_amount = float(vat_amount_str)
            vat_rate = float(vat_rate_str)

            if net_amount > 0 and vat_rate > 0:
                expected_vat = net_amount * (vat_rate / 100.0)
                difference = abs(expected_vat - vat_amount)

                if difference > 1.0:
                    line_number = (
                        self._find_text_recursive(
                            line_elem,
                            ns,
                            "lineNumber",
                        )
                        or "?"
                    )
                    self._add_finding(
                        findings,
                        NavErrorCode.VAT_LINE_ITEM_ERROR,
                        (
                            f"Line {line_number} VAT error: "
                            f"{net_amount:.2f} * {vat_rate}% = "
                            f"{expected_vat:.2f}, but shows {vat_amount:.2f}"
                        ),
                        pointer=f"line[{line_number}]",
                    )

        except (ValueError, TypeError) as exc:
            logger.debug("Could not validate line item: %s", exc)

        return vat_amount

    def _collect_vat_rates(self, root: etree._Element, ns: str) -> List[float]:
        """Collect positive VAT percentages from line items."""
        rates: List[float] = []
        for line_elem in self._findall(root, ns, "line"):
            rate_str = self._find_text_recursive(line_elem, ns, "vatPercentage")
            if not rate_str:
                continue
            try:
                rate = float(rate_str)
            except ValueError:
                continue
            if rate > 0:
                rates.append(rate)
        return rates

    def _findall(
        self,
        root: etree._Element,
        ns: str,
        tag: str,
    ) -> List[etree._Element]:
        elements = root.findall(f".//{{{ns}}}{tag}") if ns else []
        return elements or root.findall(f".//{tag}")

    def _find_text(
        self,
        element: etree._Element,
        ns: str,
        tag: str,
        default: str = "",
    ) -> str:
        return self._find_text_by_paths(
            element,
            [self._path(ns, tag), tag],
            default=default,
        )

    def _find_text_recursive(
        self,
        element: etree._Element,
        ns: str,
        tag: str,
        default: str = "",
    ) -> str:
        return self._find_text_by_paths(
            element,
            [f".//{{{ns}}}{tag}" if ns else "", f".//{tag}"],
            default=default,
        )

    @staticmethod
    def _find_text_by_paths(
        element: etree._Element,
        paths: Iterable[str],
        default: str = "",
    ) -> str:
        for path in paths:
            if not path:
                continue
            value = element.findtext(path)
            if value:
                return value.strip()
        return default

    @staticmethod
    def _path(ns: str, *segments: str) -> str:
        path = ""
        for segment in segments:
            path += f"/{{{ns}}}{segment}" if path else f".//{{{ns}}}{segment}"
        return path
