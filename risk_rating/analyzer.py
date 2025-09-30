from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple


def load_rules(path: Path | str) -> dict:
    """Load the rules JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _normalize(text: str) -> str:
    normalized = text.lower().replace("…", "...")
    return re.sub(r"\s+", " ", normalized).strip()


def _statement_present(notes: str, statement: str) -> bool:
    if not statement:
        return False
    normalized_statement = _normalize(statement)
    return normalized_statement in notes


@dataclass
class ControlStatus:
    control_id: str
    required: bool
    satisfied: bool
    text: str
    tags: Sequence[str]


class RiskRatingEvaluator:
    """Evaluate vendor risk using analyst notes."""

    SOFTWARE_PROVIDER_KEYWORDS = [
        "software provider",
        "software development",
        "develops software",
        "developing software",
        "builds software",
        "provides software",
        "saas",
        "platform as a service",
        "application development",
    ]

    def __init__(self, rules: dict):
        self.rules = rules
        self.notes: str = ""

    @classmethod
    def from_path(cls, path: Path | str) -> "RiskRatingEvaluator":
        return cls(load_rules(path))

    def evaluate(self, notes: str) -> dict:
        self.notes = _normalize(notes)
        if not self.notes:
            return {
                "rating": "no_information_provided",
                "details": {},
                "context": {
                    "handles_pii": False,
                    "remote_work_allowed": False,
                    "software_provider": False,
                },
            }

        if "not applicable" in self.notes or re.search(r"\bn/a\b", self.notes):
            return {
                "rating": "n_a",
                "details": {},
                "context": {
                    "handles_pii": False,
                    "remote_work_allowed": False,
                    "software_provider": False,
                },
            }

        context = self._build_context()
        cross_satisfied = self._apply_cross_satisfaction()
        control_status = self._evaluate_controls(context, cross_satisfied)
        incident_elements = self._collect_incident_response_elements()
        info_tech_overview = self._evaluate_info_tech_overview()
        business_continuity = self._evaluate_business_continuity(control_status)

        rating, rating_details = self._determine_rating(
            context,
            control_status,
            incident_elements,
            info_tech_overview,
            business_continuity,
        )

        return {
            "rating": rating,
            "details": rating_details,
            "context": {
                "handles_pii": context["handles_pii"],
                "remote_work_allowed": context["remote_work_allowed"],
                "software_provider": context["software_provider"],
                "incident_elements": sorted(incident_elements),
            },
        }

    def _build_context(self) -> Dict[str, bool]:
        logical_conditions = self.rules["conditions"].get("logical_access_controls", {})
        handles_pii = any(
            _statement_present(self.notes, stmt)
            for stmt in logical_conditions.get("pii_positive_statements", [])
        )

        remote_condition = (
            self.rules["conditions"].get("remote_workforce", {}).get(
                "enforce_only_if_remote_work_allowed", ""
            )
        )
        remote_allowed = bool(remote_condition) and _statement_present(
            self.notes, remote_condition
        )

        software_provider = any(
            phrase in self.notes for phrase in self.SOFTWARE_PROVIDER_KEYWORDS
        )

        return {
            "handles_pii": handles_pii,
            "remote_work_allowed": remote_allowed,
            "software_provider": software_provider,
        }

    def _apply_cross_satisfaction(self) -> Set[str]:
        cross_rules = self.rules["conditions"].get("cross_satisfaction", [])
        satisfied: Set[str] = set()
        for rule in cross_rules:
            if_any = rule.get("if_any_statement_present", [])
            for statement in if_any:
                if _statement_present(self.notes, statement):
                    satisfied.update(rule.get("then_mark_controls_met", []))
                    break
        return satisfied

    def _evaluate_controls(
        self, context: Dict[str, bool], cross_satisfied: Set[str]
    ) -> Dict[str, ControlStatus]:
        status: Dict[str, ControlStatus] = {}
        conditions = self.rules.get("conditions", {})

        def register_control(control_id: str, required: bool, satisfied: bool, text: str, tags: Sequence[str]) -> None:
            status[control_id] = ControlStatus(
                control_id=control_id,
                required=required,
                satisfied=satisfied,
                text=text,
                tags=tags,
            )

        def check_control(control: dict, required: bool = True) -> None:
            control_id = control["id"]
            control_text = control.get("text", "")
            satisfied = False
            if control_id in cross_satisfied:
                satisfied = True
            else:
                satisfied = self._statement_satisfies_control(control_id, control_text)
            register_control(control_id, required, satisfied, control_text, control.get("tags", []))

        catalog = self.rules.get("catalog", {})

        for control in catalog.get("logical_access_controls", []):
            required = True
            if (
                control["id"] == "lac_mfa_critical_or_pii"
                and conditions.get("logical_access_controls", {}).get(
                    "enforce_mfa_critical_or_pii_if_company_handles_pii", False
                )
                and not context["handles_pii"]
            ):
                required = False
            check_control(control, required)

        network_catalog = catalog.get("network_information_security", {})
        for control in network_catalog.get("pii_controls", []):
            required = not (
                conditions.get("network_information_security", {}).get(
                    "enforce_pii_controls_if_company_handles_pii", False
                )
                and not context["handles_pii"]
            )
            if (
                control["id"] == "net_pii_need_to_know"
                and conditions.get("network_information_security", {}).get(
                    "do_not_enforce_need_to_know_if_least_privilege_statement_present", False
                )
            ):
                least_privilege = status.get("lac_least_privilege")
                if least_privilege and least_privilege.satisfied:
                    register_control(
                        control["id"],
                        required=False,
                        satisfied=True,
                        text=control.get("text", ""),
                        tags=control.get("tags", []),
                    )
                    continue
            check_control(control, required)

        for control in network_catalog.get("controls", []):
            check_control(control, required=True)

        for control in catalog.get("change_mgmt_sdlc", []):
            required = context["software_provider"]
            check_control(control, required)

        for control in catalog.get("remote_workforce", []):
            required = context["remote_work_allowed"]
            check_control(control, required)

        for control in catalog.get("business_continuity", []):
            check_control(control, required=True)

        return status

    def _statement_satisfies_control(self, control_id: str, control_text: str) -> bool:
        if _statement_present(self.notes, control_text):
            return True
        if control_id and control_id in self.notes:
            return True
        words = re.split(r"\W+", control_id)
        if len(words) > 1:
            # Ensure acronym-like tokens also work
            token = " ".join(words[1:])
            if token and token in self.notes:
                return True
        # Handle negative statements overriding positives
        if control_id == "lac_passwords_encrypted_in_transit":
            negatives = self.rules["conditions"]["logical_access_controls"].get(
                "passwords_encrypted_in_transit_only_if_negative_statement_present", []
            )
            if any(_statement_present(self.notes, neg) for neg in negatives):
                return False
        return False

    def _collect_incident_response_elements(self) -> Set[str]:
        elements = set()
        for element in self.rules["catalog"].get("incident_response_elements", []):
            if _statement_present(self.notes, element):
                elements.add(element)
        return elements

    def _evaluate_info_tech_overview(self) -> Set[str]:
        required = self.rules["ratings"]["very_favorable"]["info_tech_overview"].get("required", [])
        present = set()
        for statement in required:
            if _statement_present(self.notes, statement):
                present.add(statement)
        return present

    def _evaluate_business_continuity(self, control_status: Dict[str, ControlStatus]) -> bool:
        bcp_control = control_status.get("bcp_plan")
        return bool(bcp_control and bcp_control.satisfied)

    def _determine_rating(
        self,
        context: Dict[str, bool],
        control_status: Dict[str, ControlStatus],
        incident_elements: Set[str],
        info_tech_overview: Set[str],
        business_continuity: bool,
    ) -> Tuple[str, dict]:
        ratings_order = [
            "very_favorable",
            "favorable",
            "neutral",
            "unfavorable",
        ]

        for rating in ratings_order:
            requirements = self.rules["ratings"][rating]
            if self._meets_rating(
                rating,
                requirements,
                context,
                control_status,
                incident_elements,
                info_tech_overview,
                business_continuity,
            ):
                return rating, self._build_rating_details(
                    rating,
                    requirements,
                    control_status,
                    incident_elements,
                    info_tech_overview,
                )

        # Did not meet unfavorable: automatically very unfavorable
        return "very_unfavorable", {
            "reason": "Vendor did not satisfy the minimum safeguards for an unfavorable rating.",
            "missing_controls": self._missing_required_controls(control_status),
        }

    def _meets_rating(
        self,
        rating: str,
        requirements: dict,
        context: Dict[str, bool],
        control_status: Dict[str, ControlStatus],
        incident_elements: Set[str],
        info_tech_overview: Set[str],
        business_continuity: bool,
    ) -> bool:
        if not self._meets_info_tech_overview(requirements.get("info_tech_overview", {}), info_tech_overview):
            return False

        if not self._meets_logical_access_controls(
            requirements.get("logical_access_controls", {}), control_status
        ):
            return False

        if not self._meets_network_controls(
            requirements.get("network_information_security", {}),
            context,
            control_status,
        ):
            return False

        if not self._meets_change_mgmt(
            requirements.get("change_mgmt_sdlc", {}), context, control_status
        ):
            return False

        if not self._meets_remote_workforce(
            requirements.get("remote_workforce", {}), context, control_status
        ):
            return False

        if not self._meets_incident_response(requirements.get("incident_response", {}), incident_elements):
            return False

        if not self._meets_business_continuity(requirements.get("business_continuity", {}), business_continuity):
            return False

        return True

    def _meets_info_tech_overview(self, requirement: dict, present: Set[str]) -> bool:
        required = requirement.get("required", [])
        return all(statement in present for statement in required)

    def _category_controls(self, prefix: str, status: Dict[str, ControlStatus]) -> List[ControlStatus]:
        return [ctrl for ctrl_id, ctrl in status.items() if ctrl_id.startswith(prefix)]

    def _meets_logical_access_controls(self, requirement: dict, status: Dict[str, ControlStatus]) -> bool:
        controls = self._category_controls("lac_", status)
        required_controls = [ctrl for ctrl in controls if ctrl.required]
        if requirement.get("required_all"):
            return all(ctrl.satisfied for ctrl in required_controls)
        count = sum(1 for ctrl in required_controls if ctrl.satisfied)
        if count < requirement.get("min_count", 0):
            return False
        tag = requirement.get("must_include_tag")
        if tag:
            if not any(ctrl.satisfied and tag in ctrl.tags for ctrl in required_controls):
                return False
        return True

    def _meets_network_controls(
        self,
        requirement: dict,
        context: Dict[str, bool],
        status: Dict[str, ControlStatus],
    ) -> bool:
        pii_controls = [ctrl for ctrl in self._category_controls("net_pii_", status) if ctrl.required]
        if requirement.get("pii_controls_required_if_company_handles_pii") and context["handles_pii"]:
            if not pii_controls:
                return False
            if not all(ctrl.satisfied for ctrl in pii_controls):
                return False

        net_controls = [
            ctrl
            for ctrl in status.values()
            if ctrl.control_id.startswith("net_") and not ctrl.control_id.startswith("net_pii_")
        ]
        required_controls = [ctrl for ctrl in net_controls if ctrl.required]
        if requirement.get("controls_required_all"):
            return all(ctrl.satisfied for ctrl in required_controls)

        count = sum(1 for ctrl in required_controls if ctrl.satisfied)
        if count < requirement.get("min_count", 0):
            return False
        tag = requirement.get("must_include_tag")
        if tag and not any(ctrl.satisfied and tag in ctrl.tags for ctrl in required_controls):
            return False
        return True

    def _meets_change_mgmt(self, requirement: dict, context: Dict[str, bool], status: Dict[str, ControlStatus]) -> bool:
        controls = self._category_controls("chg_", status)
        required_controls = [ctrl for ctrl in controls if ctrl.required]
        if not context["software_provider"]:
            return True
        if requirement.get("required_all"):
            return all(ctrl.satisfied for ctrl in required_controls)
        if requirement.get("require_change_mgmt_process"):
            change_mgmt = status.get("chg_change_mgmt_process")
            if not change_mgmt or not change_mgmt.satisfied:
                return False
        min_count_from = requirement.get("min_count_from", [])
        if min_count_from:
            satisfied_count = sum(
                1
                for control_id in min_count_from
                if status.get(control_id) and status[control_id].satisfied
            )
            if satisfied_count < requirement.get("min_count", 0):
                return False
        else:
            count = sum(1 for ctrl in required_controls if ctrl.satisfied)
            if count < requirement.get("min_count", 0):
                return False
        return True

    def _meets_remote_workforce(
        self,
        requirement: dict,
        context: Dict[str, bool],
        status: Dict[str, ControlStatus],
    ) -> bool:
        controls = self._category_controls("rw_", status)
        required_controls = [ctrl for ctrl in controls if ctrl.required]
        if not context["remote_work_allowed"]:
            return True
        if requirement.get("required_all"):
            return all(ctrl.satisfied for ctrl in required_controls)
        count = sum(1 for ctrl in required_controls if ctrl.satisfied)
        if count < requirement.get("min_count", 0):
            return False
        return True

    def _meets_incident_response(self, requirement: dict, elements: Set[str]) -> bool:
        min_elements = requirement.get("min_elements")
        if min_elements is None:
            return True
        return len(elements) >= min_elements

    def _meets_business_continuity(self, requirement: dict, has_plan: bool) -> bool:
        if not requirement:
            return True
        if requirement.get("required") and not has_plan:
            return False
        return True

    def _build_rating_details(
        self,
        rating: str,
        requirements: dict,
        status: Dict[str, ControlStatus],
        incident_elements: Set[str],
        info_tech_overview: Set[str],
    ) -> dict:
        details = {
            "rating": rating,
            "satisfied_controls": sorted(
                ctrl.control_id for ctrl in status.values() if ctrl.satisfied and ctrl.required
            ),
            "missing_controls": self._missing_required_controls(status),
            "incident_response_elements": sorted(incident_elements),
            "info_tech_overview": sorted(info_tech_overview),
        }
        return details

    def _missing_required_controls(self, status: Dict[str, ControlStatus]) -> List[str]:
        missing = [ctrl.control_id for ctrl in status.values() if ctrl.required and not ctrl.satisfied]
        missing.sort()
        return missing

