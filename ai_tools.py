# -*- coding: utf-8 -*-
"""Real-time AI Tools Framework for REL8 Stack.

Provides autonomous and interactive tools for the AI Hub to query, inspect,
simulate, mutate, and operate on live EMV relay stack state, APDU streams,
issuer authorizations, profiles, and runtime logs.
"""

from __future__ import annotations

import ast
import difflib
import inspect
import io
import json
import logging
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("AITools")

# Import stack modules safely
try:
    import constants
    import emv
    import guard
    import issuer_profiles
    import issuer_simulator
    import mod_emv_synthesizer
    import mutations
    import parser
    import protocol
    import tlv
    import utils
    import emv_lab1
except ImportError as err:
    logger.warning(f"Some stack modules could not be imported immediately: {err}")


@dataclass
class ToolResult:
    """Encapsulates the result of a tool execution."""
    tool_name: str
    success: bool
    data: Any
    error: Optional[str] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool_name,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_time_ms": round(self.execution_time_ms, 2),
        }

    def format_text(self) -> str:
        """Formatted Markdown representation for AI prompt or chat display."""
        if self.success:
            if isinstance(self.data, (dict, list)):
                formatted_data = json.dumps(self.data, indent=2, default=str)
            else:
                formatted_data = str(self.data)
            return (
                f"```json\n"
                f"{formatted_data}\n"
                f"```"
            )
        else:
            return f"❌ **Error executing `{self.tool_name}`:** {self.error}"


@dataclass
class AITool:
    """Represents a callable tool with JSON schema metadata for LLM function calling."""
    name: str
    description: str
    parameters: Dict[str, Any]
    handler: Callable[..., Any]
    category: str = "general"

    def execute(self, **kwargs) -> ToolResult:
        t0 = time.time()
        try:
            res = self.handler(**kwargs)
            lat = (time.time() - t0) * 1000.0
            return ToolResult(tool_name=self.name, success=True, data=res, execution_time_ms=lat)
        except Exception as exc:
            lat = (time.time() - t0) * 1000.0
            err_msg = f"{type(exc).__name__}: {str(exc)}\n{traceback.format_exc()}"
            logger.error(f"Error in tool '{self.name}': {err_msg}")
            return ToolResult(tool_name=self.name, success=False, data=None, error=str(exc), execution_time_ms=lat)

    def to_openai_schema(self) -> Dict[str, Any]:
        """Converts to OpenAI / Ollama function calling schema format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class AIToolRegistry:
    """Central registry and execution coordinator for all real-time AI tools."""

    def __init__(
        self,
        project_runtime: Optional[Any] = None,
        app_runtime_getter: Optional[Callable[[], Any]] = None,
        relay_state_getter: Optional[Callable[[], Dict[str, Any]]] = None,
        outcome_guard_getter: Optional[Callable[[], Any]] = None,
        logs_dir: Optional[Path] = None,
    ) -> None:
        self.tools: Dict[str, AITool] = {}
        self.project_runtime = project_runtime
        self.app_runtime_getter = app_runtime_getter
        self.relay_state_getter = relay_state_getter
        self.outcome_guard_getter = outcome_guard_getter
        self.logs_dir = logs_dir or (Path(__file__).parent / "logs")
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.execution_history: List[ToolResult] = []
        self.omnipotent_mode: bool = False
        self.memory_store: Optional[Any] = None
        self.emv_lab: Optional[Any] = None

        self._register_default_tools()

    def set_omnipotent_mode(self, enabled: bool) -> None:
        """Toggles Omnipotent EMV Flow God Mode on/off."""
        self.omnipotent_mode = bool(enabled)

    def register(self, tool: AITool) -> None:
        self.tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[AITool]:
        return self.tools.get(name)

    def list_tools(self) -> List[AITool]:
        return list(self.tools.values())

    def get_openai_tools_schema(self) -> List[Dict[str, Any]]:
        return [tool.to_openai_schema() for tool in self.tools.values()]

    def execute_tool(self, name: str, **kwargs) -> ToolResult:
        tool = self.tools.get(name)
        if not tool:
            res = ToolResult(
                tool_name=name,
                success=False,
                data=None,
                error=f"Tool '{name}' is not registered. Available: {list(self.tools.keys())}",
            )
            self.execution_history.append(res)
            return res

        res = tool.execute(**kwargs)
        self.execution_history.append(res)
        return res

    # =========================================================================
    # TOOL IMPLEMENTATIONS
    # =========================================================================

    def _tool_get_stack_status(self) -> Dict[str, Any]:
        """Gathers real-time telemetry from UDP relay, OutcomeGuard, socket connections, and runtime."""
        status: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_sec": 0.0,
            "relay_running": False,
            "guard_phase": "IDLE",
            "peer_reader": "DISCONNECTED",
            "peer_card": "DISCONNECTED",
            "packets_rx": 0,
            "packets_tx": 0,
            "active_flags": {},
            "arqc_cache": {},
        }

        if self.relay_state_getter:
            try:
                live_dict = self.relay_state_getter()
                if isinstance(live_dict, dict):
                    status.update(live_dict)
            except Exception as exc:
                status["getter_error"] = str(exc)

        if self.outcome_guard_getter:
            try:
                g = self.outcome_guard_getter()
                if g:
                    status["guard_phase"] = str(getattr(g, "phase", "UNKNOWN"))
                    if hasattr(g, "arqc_cache"):
                        status["arqc_cache"] = {
                            "atc": getattr(g.arqc_cache, "atc", None),
                            "ac": getattr(g.arqc_cache, "ac", None),
                            "iad": getattr(g.arqc_cache, "iad", None),
                            "is_complete": g.arqc_cache.is_complete() if hasattr(g.arqc_cache, "is_complete") else False,
                        }
            except Exception as exc:
                status["guard_error"] = str(exc)

        if self.project_runtime:
            try:
                status["loaded_modules_count"] = len(self.project_runtime.modules)
                status["loaded_modules"] = list(self.project_runtime.modules.keys())[:10]
            except Exception:
                pass

        return status

    def _tool_parse_apdu(self, hex_apdu: str, direction: str = "auto") -> Dict[str, Any]:
        """Parses Command APDU (CAPDU) or Response APDU (RAPDU) in real time with TLV decoding."""
        clean_hex = re.sub(r"[^0-9A-Fa-f]", "", hex_apdu).upper()
        if not clean_hex:
            raise ValueError("Provided APDU hex string is empty or invalid.")

        raw_bytes = bytes.fromhex(clean_hex)
        res: Dict[str, Any] = {
            "raw_hex": clean_hex,
            "length_bytes": len(raw_bytes),
            "type": "UNKNOWN",
            "details": {},
        }

        # Check if CAPDU
        is_capdu = False
        if direction.lower() == "capdu" or (direction.lower() == "auto" and len(raw_bytes) >= 4 and clean_hex[-4:] not in ("9000", "6F00", "6985", "6A82", "6700", "6D00")):
            try:
                capdu = protocol.CommandAPDU.from_bytes(raw_bytes)
                cla = capdu.cla
                ins = capdu.ins
                p1 = capdu.p1
                p2 = capdu.p2
                data = capdu.data
                le = capdu.le

                ins_name = guard.INS_NAMES.get(ins, f"UNKNOWN_0x{ins:02X}")
                res["type"] = "CAPDU"
                res["details"] = {
                    "cla": f"0x{cla:02X}",
                    "ins": f"0x{ins:02X} ({ins_name})",
                    "p1": f"0x{p1:02X}",
                    "p2": f"0x{p2:02X}",
                    "lc": len(data),
                    "data_hex": data.hex().upper(),
                    "le": le,
                }
                is_capdu = True
                # Parse data payload if TLV
                if data:
                    try:
                        nodes, errs = parser.parse_ber_tlv(data)
                        res["details"]["data_tlv_tags"] = [n.tag for n in nodes]
                    except Exception:
                        pass
            except Exception:
                pass

        if not is_capdu:
            # Parse as RAPDU
            res["type"] = "RAPDU"
            sw = raw_bytes[-2:].hex().upper() if len(raw_bytes) >= 2 else "NONE"
            body = raw_bytes[:-2] if len(raw_bytes) >= 2 else raw_bytes
            sw_meaning = "SUCCESS (OK)" if sw == "9000" else f"STATUS WORD: {sw}"
            if sw == "6985":
                sw_meaning = "Conditions of use not satisfied (Command not allowed)"
            elif sw == "6A82":
                sw_meaning = "File or application not found"
            elif sw == "6700":
                sw_meaning = "Wrong length"
            elif sw == "6F00":
                sw_meaning = "No precise diagnosis / General failure"

            res["details"] = {
                "body_hex": body.hex().upper(),
                "sw": sw,
                "sw_meaning": sw_meaning,
            }

            # TLV breakdown of RAPDU body
            if body:
                try:
                    nodes, errs = parser.parse_ber_tlv(body)
                    tlv_breakdown = []
                    for n in nodes:
                        node_dict = {
                            "tag": n.tag,
                            "tag_name": self._lookup_tag_name(n.tag),
                            "length": len(n.value),
                            "value_hex": n.value.hex().upper(),
                        }
                        if n.children:
                            node_dict["children"] = [
                                {
                                    "tag": c.tag,
                                    "tag_name": self._lookup_tag_name(c.tag),
                                    "length": len(c.value),
                                    "value_hex": c.value.hex().upper(),
                                }
                                for c in n.children
                            ]
                        tlv_breakdown.append(node_dict)
                    res["details"]["tlv_tree"] = tlv_breakdown
                    if errs:
                        res["details"]["tlv_errors"] = errs
                except Exception as exc:
                    res["details"]["tlv_error"] = str(exc)

        return res

    def _lookup_tag_name(self, tag_hex: str) -> str:
        """Looks up EMV tag names from constants or known dictionaries."""
        tag_hex = tag_hex.upper()
        known = {
            "4F": "Application Identifier (AID)",
            "50": "Application Label",
            "57": "Track 2 Equivalent Data",
            "5A": "Application Primary Account Number (PAN)",
            "5F20": "Cardholder Name",
            "5F24": "Application Expiration Date",
            "5F25": "Application Effective Date",
            "5F28": "Issuer Country Code",
            "5F2A": "Transaction Currency Code",
            "5F34": "Application Primary Account Number (PAN) Sequence Number",
            "6F": "FCI Template",
            "70": "Read Record Template",
            "77": "Response Message Template Format 2",
            "80": "Response Message Template Format 1",
            "82": "Application Interchange Profile (AIP)",
            "84": "Dedicated File (DF) Name",
            "87": "Application Priority Indicator",
            "88": "Short File Identifier (SFI)",
            "8C": "Card Risk Management Data Object List 1 (CDOL1)",
            "8D": "Card Risk Management Data Object List 2 (CDOL2)",
            "8E": "Cardholder Verification Method (CVM) List",
            "94": "Application File Locator (AFL)",
            "95": "Terminal Verification Results (TVR)",
            "9A": "Transaction Date",
            "9C": "Transaction Type",
            "9F02": "Amount, Authorized (Numeric)",
            "9F03": "Amount, Other (Numeric)",
            "9F08": "Application Version Number (Card)",
            "9F09": "Application Version Number (Terminal)",
            "9F10": "Issuer Application Data (IAD)",
            "9F19": "Deleted Token Format",
            "9F1A": "Terminal Country Code",
            "9F26": "Application Cryptogram (ARQC/TC/AAC)",
            "9F27": "Cryptogram Information Data (CID)",
            "9F33": "Terminal Capabilities",
            "9F34": "Cardholder Verification Method (CVM) Results",
            "9F35": "Terminal Type",
            "9F36": "Application Transaction Counter (ATC)",
            "9F37": "Unpredictable Number (UN)",
            "9F38": "Processing Options Data Object List (PDOL)",
            "9F4B": "Signed Dynamic Application Data (SDAD)",
            "9F6C": "Card Transaction Qualifiers (CTQ)",
            "9F66": "Terminal Transaction Qualifiers (TTQ)",
            "A5": "File Control Information (FCI) Proprietary Template",
            "BF0C": "FCI Issuer Discretionary Data",
        }
        return known.get(tag_hex, f"Tag 0x{tag_hex}")

    def _tool_parse_tlv(self, hex_tlv: str) -> Dict[str, Any]:
        """Hierarchically decodes BER-TLV hex byte stream into structured tree."""
        clean_hex = re.sub(r"[^0-9A-Fa-f]", "", hex_tlv).upper()
        if not clean_hex:
            raise ValueError("Empty TLV hex string provided.")

        raw_bytes = bytes.fromhex(clean_hex)
        nodes, errors = parser.parse_ber_tlv(raw_bytes)

        def node_to_dict(n: parser.TlvNode) -> Dict[str, Any]:
            item = {
                "tag": n.tag,
                "name": self._lookup_tag_name(n.tag),
                "length": len(n.value),
                "value_hex": n.value.hex().upper(),
            }
            if n.children:
                item["children"] = [node_to_dict(c) for c in n.children]
            return item

        return {
            "total_bytes": len(raw_bytes),
            "parsed_nodes_count": len(nodes),
            "nodes": [node_to_dict(n) for n in nodes],
            "errors": errors,
        }

    def _tool_simulate_apdu_mutation(
        self,
        capdu_hex: str = "",
        rapdu_hex: str = "",
        mutation_type: str = "gpo",
        clear_tvr: bool = True,
        set_cvm_list: str = "none",
        cdcvm_verified: bool = True,
    ) -> Dict[str, Any]:
        """Simulates real-time APDU mutations (e.g. CDCVM bypass, TVR zeroing, ARPC rewrite, second GAC TC forge)."""
        clean_rapdu = re.sub(r"[^0-9A-Fa-f]", "", rapdu_hex).upper()
        rapdu_bytes = bytes.fromhex(clean_rapdu) if clean_rapdu else b"\x77\x0E\x82\x02\x38\x00\x94\x08\x08\x01\x01\x00\x10\x01\x01\x01\x90\x00"

        res: Dict[str, Any] = {
            "mutation_type": mutation_type,
            "original_hex": rapdu_bytes.hex().upper(),
            "mutated_hex": "",
            "changed": False,
            "explanation": "",
        }

        m_type = mutation_type.lower()
        if "gpo" in m_type or m_type == "all":
            mutated_bytes, changed = mutations.mutate_gpo_response(
                rapdu_bytes,
                cdcvm_verified=cdcvm_verified,
                clear_tvr=clear_tvr,
                set_cvm_list=set_cvm_list if set_cvm_list != "none" else None,
            )
            res["mutated_hex"] = mutated_bytes.hex().upper()
            res["changed"] = changed
            res["explanation"] = (
                f"GPO Mutation executed. CDCVM verified={cdcvm_verified}, TVR cleared={clear_tvr}, "
                f"CVM list={set_cvm_list}. Result size: {len(mutated_bytes)} bytes."
            )
        elif "tc" in m_type or "forge_gac" in m_type:
            # Forge 2nd GAC TC
            cache = emv.ArqcCache()
            cache.cid = 0x80  # ARQC
            cache.atc = bytes.fromhex("001A")
            cache.ac = bytes.fromhex("A1B2C3D4E5F60708")
            cache.iad = bytes.fromhex("06010A03000000")
            cache.template = constants.TEMPLATE_77
            forged = mutations.forge_2nd_gac(
                cache,
                forced_cid=constants.CID_TC,
                brand=constants.BRAND_UNKNOWN,
            )
            if forged is None:
                raise ValueError(f"No 2nd-GAC forge handler for template {cache.template!r}")
            res["mutated_hex"] = forged.hex().upper()
            res["changed"] = True
            res["explanation"] = "Synthesized second GENERATE AC TC (0x40) response from the canonical ArqcCache dispatcher."
        elif "arpc" in m_type or "rewrite" in m_type:
            # ARPC rewrite — use the canonical Tag-91 CAPDU rewriter.
            original_arpc = bytes.fromhex("008200000A11223344556677883035")
            rewritten, note = mutations.rewrite_arpc_in_capdu(original_arpc)
            res["mutated_hex"] = rewritten.hex().upper()
            res["changed"] = rewritten != original_arpc
            res["explanation"] = note or "ARPC rewrite completed; no matching Tag 91 ARC field was found."
        else:
            res["explanation"] = f"Unknown mutation type '{mutation_type}'. Supported: gpo, tc, arpc, all."

        return res

    def _tool_evaluate_issuer_authorization(
        self,
        pan: str = "5555444433332222",
        amount_minor: int = 1000,
        currency_numeric: int = 826,
        atc: int = 1,
        ttq_hex: str = "36004000",
        ctq_hex: str = "8000",
        arqc_hex: str = "0102030405060708",
        cdcvm_performed: bool = False,
        bind_ctq: bool = True,
        require_cvm_consistency: bool = True,
    ) -> Dict[str, Any]:
        """Evaluates live issuer authorization and cryptogram verification using SyntheticIssuer."""
        issuer = issuer_simulator.SyntheticIssuer(
            bind_ctq=bind_ctq,
            require_cvm_consistency=require_cvm_consistency,
        )
        req = issuer_simulator.AuthorizationRequest(
            pan=str(pan).strip(),
            amount_minor=int(amount_minor),
            currency_numeric=int(currency_numeric),
            atc=int(atc),
            ttq=bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", ttq_hex)),
            ctq=bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", ctq_hex)),
            arqc=bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", arqc_hex)),
            cdcvm_performed=bool(cdcvm_performed),
        )

        signed_req = issuer.sign(req)
        auth_resp = issuer.authorize(signed_req)

        return {
            "request": signed_req.to_dict(),
            "authorization_response": auth_resp.to_dict(),
            "verdict": "APPROVED (00)" if auth_resp.approved else f"DECLINED ({auth_resp.response_code})",
            "arqc_valid": auth_resp.arqc_valid,
            "cvm_consistent": auth_resp.cvm_consistent,
            "signature_hex": signed_req.signature.hex().upper(),
        }

    def _tool_inspect_issuer_profile(self, query: str) -> Dict[str, Any]:
        """Queries issuer profiles table and profile files for country codes, CVM thresholds, and rules."""
        q = str(query).strip().upper()
        found_country = None
        country_code = None

        # Search issuer_profiles dictionary
        for code, prof in issuer_profiles.ISSUER_PROFILES.items():
            if code.upper() == q or q in prof.get("country", "").upper():
                found_country = prof
                country_code = code
                break

        # Also search profiles/ directory JSON files
        profile_files = []
        profiles_dir = Path(__file__).parent / "profiles"
        if profiles_dir.exists():
            for pf in profiles_dir.glob("*.json"):
                try:
                    data = json.loads(pf.read_text(encoding="utf-8", errors="ignore"))
                    if q in pf.name.upper() or q in json.dumps(data).upper():
                        profile_files.append({"filename": pf.name, "summary": data})
                except Exception:
                    pass

        return {
            "query": query,
            "issuer_table_match": {
                "country_code": country_code,
                "profile": found_country,
            } if found_country else None,
            "matching_profile_files": profile_files,
            "total_profiles_available": len(issuer_profiles.ISSUER_PROFILES),
        }

    def _tool_list_profiles(self) -> Dict[str, Any]:
        """Lists all issuer profiles and JSON card profiles available in the stack."""
        table_profiles = []
        for code, p in issuer_profiles.ISSUER_PROFILES.items():
            table_profiles.append({
                "country_code": code,
                "country": p.get("country"),
                "cvm_threshold": p.get("cvm_threshold"),
                "cvm_default": p.get("cvm_default"),
                "notes": p.get("notes"),
            })

        json_profiles = []
        profiles_dir = Path(__file__).parent / "profiles"
        if profiles_dir.exists():
            for f in sorted(profiles_dir.glob("*.json")):
                json_profiles.append(f.name)

        return {
            "total_country_profiles": len(table_profiles),
            "country_profiles_sample": table_profiles[:12],
            "profile_json_files": json_profiles,
        }

    def _tool_search_logs(self, query: str = "", log_file: str = "", max_lines: int = 50) -> Dict[str, Any]:
        """Searches live logs and transaction logs in real time for keywords, APDUs, or errors."""
        q_upper = query.strip().upper()
        results = []
        matched_files = 0

        target_files = []
        if log_file:
            target_p = self.logs_dir / log_file
            if target_p.exists():
                target_files.append(target_p)
            else:
                alt = Path(__file__).parent / "logs" / log_file
                if alt.exists():
                    target_files.append(alt)
        else:
            target_files = sorted(self.logs_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[:10]

        for lf in target_files:
            try:
                lines = lf.read_text(encoding="utf-8", errors="replace").splitlines()
                file_matches = []
                for idx, line in enumerate(lines, 1):
                    if not q_upper or q_upper in line.upper():
                        file_matches.append({"line_num": idx, "text": line})
                        if len(file_matches) >= max_lines:
                            break
                if file_matches:
                    matched_files += 1
                    results.append({
                        "file": lf.name,
                        "size_bytes": lf.stat().st_size,
                        "matches_count": len(file_matches),
                        "matches": file_matches[:max_lines],
                    })
            except Exception as exc:
                results.append({"file": lf.name, "error": str(exc)})

        return {
            "query": query,
            "searched_files_count": len(target_files),
            "matched_files_count": matched_files,
            "results": results,
        }

    def _tool_get_recent_trace(self, max_entries: int = 20) -> Dict[str, Any]:
        """Retrieves recent live APDU exchanges and guard transitions from transaction log files."""
        log_files = sorted(self.logs_dir.glob("tx_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not log_files:
            log_files = sorted(self.logs_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)

        if not log_files:
            return {"message": "No transaction log files found in logs/ directory.", "traces": []}

        latest_log = log_files[0]
        try:
            analyzer = parser.RelayAnalyzer(latest_log)
            analyzer.analyze()
            traces = []
            for ex in analyzer.exchanges[-max_entries:]:
                traces.append({
                    "transaction": ex.transaction,
                    "epoch": ex.epoch,
                    "capdu_hex": ex.capdu_hex,
                })
            return {
                "latest_log_file": latest_log.name,
                "epochs_count": len(analyzer.epochs),
                "total_exchanges": len(analyzer.exchanges),
                "recent_traces": traces,
            }
        except Exception as exc:
            return {"error": str(exc), "latest_log_file": latest_log.name}

    def _tool_reset_guard_fsm(self) -> Dict[str, Any]:
        """Resets OutcomeGuard state machine to IDLE in real time."""
        if self.outcome_guard_getter:
            try:
                g = self.outcome_guard_getter()
                if g and hasattr(g, "reset"):
                    g.reset()
                    return {"success": True, "message": "OutcomeGuard state machine reset to Phase.IDLE."}
                elif g and hasattr(g, "phase"):
                    g.phase = guard.Phase.IDLE
                    return {"success": True, "message": "OutcomeGuard phase explicitly set to Phase.IDLE."}
            except Exception as exc:
                return {"success": False, "error": str(exc)}
        return {"success": True, "message": "OutcomeGuard reset signal dispatched."}

    def _tool_remember_fact(self, key: str, value: str, category: str = "general") -> Dict[str, Any]:
        """Stores a durable fact, decision, or finding into long-term persistent memory."""
        if not self.memory_store:
            return {"error": "Long-term memory store is not attached to the tool registry."}
        return self.memory_store.remember(key, value, category=category)

    def _tool_recall_memory(self, query: str = "", max_results: int = 10) -> Dict[str, Any]:
        """Searches long-term persistent memory for facts matching a query, or lists recent memories."""
        if not self.memory_store:
            return {"error": "Long-term memory store is not attached to the tool registry."}
        results = self.memory_store.recall(query=query, max_results=max_results)
        return {
            "query": query,
            "matches_count": len(results),
            "total_facts": self.memory_store.fact_count(),
            "digest_active": bool(self.memory_store.get_digest()),
            "memories": results,
        }

    def _tool_forget_fact(self, key: str) -> Dict[str, Any]:
        """Permanently removes a fact from long-term persistent memory."""
        if not self.memory_store:
            return {"error": "Long-term memory store is not attached to the tool registry."}
        removed = self.memory_store.forget(key)
        return {
            "removed": removed,
            "key": key,
            "remaining_facts": self.memory_store.fact_count(),
        }

    def _tool_inspect_project_code(self, module_name: str, symbol_name: str = "") -> Dict[str, Any]:
        """Inspects classes, functions, and docstrings of any module in the stack in real time."""
        m_name = module_name.strip()
        if not self.project_runtime:
            return {"error": "ProjectRuntime is not initialized."}

        access_info = {
            "omnipotent_mode": self.omnipotent_mode,
            "filesystem_access": (
                "FULL_DISK_WRITE_ACCESS_UNLOCKED (Code on disk can be modified via modify_project_code)"
                if self.omnipotent_mode
                else "READ_ONLY (Toggle Omnipotent EMV Flow God Mode to unlock disk code modifications)"
            ),
        }

        mod = self.project_runtime.modules.get(m_name)
        if mod is None:
            # Try fuzzy match
            for name, candidate in self.project_runtime.modules.items():
                if m_name.lower() in name.lower():
                    mod = candidate
                    m_name = name
                    break

        if mod is None or not inspect.ismodule(mod):
            result: Dict[str, Any] = {
                "error": f"Module '{module_name}' not found in runtime.",
                "available_modules": list(self.project_runtime.modules.keys()),
            }
            info = getattr(self.project_runtime, "module_infos", {}).get(m_name)
            if info is not None:
                result["module_status"] = getattr(info, "status", None)
                result["load_error"] = getattr(info, "error", None)
            return result

        def _safe_signature(obj: Any) -> str:
            try:
                return str(inspect.signature(obj))
            except (TypeError, ValueError):
                return "(...)"

        def _safe_line_number(obj: Any) -> Optional[int]:
            try:
                return inspect.getsourcelines(obj)[1]
            except (OSError, TypeError):
                return None

        mod_name_real = getattr(mod, "__name__", m_name)
        functions = [
            (name, obj)
            for name, obj in inspect.getmembers(mod, inspect.isfunction)
            if getattr(obj, "__module__", None) == mod_name_real
        ]
        classes = [
            (name, obj)
            for name, obj in inspect.getmembers(mod, inspect.isclass)
            if getattr(obj, "__module__", None) == mod_name_real
        ]

        if symbol_name:
            s_name = symbol_name.strip()
            # Search functions or classes
            for name, fn in functions:
                if name.lower() == s_name.lower():
                    return {
                        "module": m_name,
                        "type": "function",
                        "name": name,
                        "signature": _safe_signature(fn),
                        "docstring": inspect.getdoc(fn) or "",
                        "line_number": _safe_line_number(fn),
                        **access_info,
                    }
            for name, cls in classes:
                if name.lower() == s_name.lower():
                    methods = [
                        m_name
                        for m_name, m_obj in inspect.getmembers(cls, inspect.isfunction)
                        if m_obj.__qualname__.split(".")[0] == cls.__name__
                    ]
                    return {
                        "module": m_name,
                        "type": "class",
                        "name": name,
                        "docstring": inspect.getdoc(cls) or "",
                        "methods": methods,
                        "line_number": _safe_line_number(cls),
                        **access_info,
                    }
            return {
                "error": f"Symbol '{symbol_name}' not found in module '{m_name}'.",
                "available_functions": [name for name, _ in functions],
                "available_classes": [name for name, _ in classes],
            }

        constants = []
        for name, value in vars(mod).items():
            if name.isupper() and isinstance(value, (int, float, str, bytes, bool, tuple, frozenset)):
                constants.append(name)

        return {
            "module": m_name,
            "file": getattr(mod, "__file__", None),
            "docstring": inspect.getdoc(mod) or "",
            "classes_count": len(classes),
            "classes": [
                {
                    "name": name,
                    "methods": [
                        m_name
                        for m_name, m_obj in inspect.getmembers(cls, inspect.isfunction)
                        if m_obj.__qualname__.split(".")[0] == cls.__name__
                    ],
                    "docstring": (inspect.getdoc(cls) or "")[:100],
                }
                for name, cls in classes
            ],
            "functions_count": len(functions),
            "functions": [
                {
                    "name": name,
                    "signature": _safe_signature(fn),
                    "docstring": (inspect.getdoc(fn) or "")[:100],
                }
                for name, fn in functions[:20]
            ],
            "constants": constants[:20],
            **access_info,
        }

    def _tool_inject_packet(
        self,
        apdu_hex: str,
        target: str = "auto",
        frame_type: str = "auto",
        epoch: Optional[int] = None,
        seq: Optional[int] = None,
        force_guard_bypass: bool = True,
    ) -> Dict[str, Any]:
        """Directly injects arbitrary raw APDUs or protocol frames into the live relay stack, socket, or peer streams."""
        if not self.omnipotent_mode:
            raise PermissionError(
                "Direct packet injection is restricted in standard Controller Mode. "
                "Toggle 'Omnipotent EMV Flow God Mode' ON in the AI Hub to enable direct stack write-access and packet injection."
            )

        clean_hex = re.sub(r"[^0-9A-Fa-f]", "", apdu_hex).upper()
        if not clean_hex:
            raise ValueError("Provided APDU/packet hex string is empty or invalid.")

        raw_bytes = bytes.fromhex(clean_hex)
        t_str = target.lower().strip()
        f_type = frame_type.lower().strip()

        # Determine SID if frame_type auto
        sid = 0x01  # SID_CAPDU default
        if f_type == "rapdu" or (f_type == "auto" and (t_str in ("reader", "terminal") or clean_hex.endswith("9000") or clean_hex.endswith("6F00"))):
            sid = 0x02  # SID_RAPDU
        elif f_type == "ctrl" or t_str == "ctrl":
            sid = 0x05  # SID_CTRL
        elif f_type == "capdu" or t_str in ("emulator", "card"):
            sid = 0x01  # SID_CAPDU

        active_srv = None
        if self.app_runtime_getter:
            try:
                app_rt = self.app_runtime_getter()
                if app_rt and hasattr(app_rt, "main_window"):
                    active_srv = getattr(app_rt.main_window, "relay_server", None)
            except Exception:
                pass

        if not active_srv and self.project_runtime:
            try:
                active_srv = getattr(self.project_runtime, "relay_server", None)
            except Exception:
                pass

        injected_peers = []
        transmission_details = []
        actual_epoch = epoch if epoch is not None else (getattr(active_srv, "active_epoch", 1) if active_srv else 1)

        if active_srv and hasattr(active_srv, "sock") and active_srv.sock:
            reader_addr = getattr(active_srv, "reader_addr", None)
            emulator_addr = getattr(active_srv, "emulator_addr", None)

            targets_to_send: List[Tuple[str, Tuple[str, int]]] = []
            if t_str in ("reader", "terminal", "pcd"):
                if reader_addr:
                    targets_to_send.append(("reader", reader_addr))
            elif t_str in ("emulator", "card", "picc"):
                if emulator_addr:
                    targets_to_send.append(("emulator", emulator_addr))
            elif t_str in ("both", "broadcast"):
                if reader_addr:
                    targets_to_send.append(("reader", reader_addr))
                if emulator_addr:
                    targets_to_send.append(("emulator", emulator_addr))
            else:  # auto
                if sid == 0x02 and reader_addr:
                    targets_to_send.append(("reader", reader_addr))
                elif sid == 0x01 and emulator_addr:
                    targets_to_send.append(("emulator", emulator_addr))
                else:
                    if reader_addr:
                        targets_to_send.append(("reader", reader_addr))
                    if emulator_addr:
                        targets_to_send.append(("emulator", emulator_addr))

            for peer_label, addr in targets_to_send:
                try:
                    sent = active_srv._send_frame(addr, sid, raw_bytes)
                    transmission_details.append({
                        "peer": peer_label,
                        "address": f"{addr[0]}:{addr[1]}" if isinstance(addr, (list, tuple)) else str(addr),
                        "sent_success": sent,
                    })
                    if sent:
                        injected_peers.append(peer_label)
                except Exception as exc:
                    transmission_details.append({
                        "peer": peer_label,
                        "error": str(exc),
                    })

        # Record in logger history if available
        try:
            import logger as rel8_logger
            rel8_logger._record_apdu(
                transaction=1,
                epoch=actual_epoch,
                direction="INJECT_TX" if sid == 0x01 else "INJECT_RX",
                cmd_name=f"OMNIPOTENT_INJECT ({'CAPDU' if sid == 0x01 else 'RAPDU'})",
                raw_bytes=raw_bytes,
                sw_hex=clean_hex[-4:] if len(clean_hex) >= 4 else "9000",
                duration_ms=0.0,
            )
        except Exception:
            pass

        return {
            "status": "PACKET_INJECTED",
            "omnipresent_flow_god": True,
            "apdu_hex": clean_hex,
            "bytes_length": len(raw_bytes),
            "target": target,
            "frame_type": "CAPDU" if sid == 0x01 else ("RAPDU" if sid == 0x02 else "CTRL"),
            "sid": sid,
            "epoch": actual_epoch,
            "injected_peers": injected_peers,
            "transmissions": transmission_details,
            "message": f"⚡ Omnipotent EMV Flow God successfully injected {len(raw_bytes)} bytes into live flow ({' -> '.join(injected_peers) if injected_peers else 'Local Relay Queue/Stack'}).",
        }



    def _tool_modify_project_code(
            self,
            file_path: str,
            content: Optional[str] = None,
            action: str = "overwrite",
            search_text: Optional[str] = None,
            replace_text: Optional[str] = None,
            backup: bool = True,
    ) -> Dict[str, Any]:
        """Modifies, patches, or updates source code files directly on disk in real time."""

        if not self.omnipotent_mode:
            raise PermissionError(
                "Direct disk code modification is restricted in standard Controller Mode. "
                "Toggle 'Omnipotent EMV Flow God Mode' ON in the AI Hub "
                "to enable direct file-system write access."
            )

        if not file_path or not file_path.strip():
            raise ValueError("Target file_path must not be empty.")

        action_clean = (action or "overwrite").lower().strip()

        if action_clean not in {"overwrite", "patch", "append"}:
            raise ValueError(
                f"Unknown modification action: {action}. "
                "Use 'overwrite', 'patch', or 'append'."
            )

        # --------------------------------------------------------
        # Resolve target path
        # --------------------------------------------------------

        p = Path(file_path.strip())
        root_dir = Path(__file__).parent.resolve()

        if not p.is_absolute():
            resolved_path = (root_dir / p).resolve()
        else:
            resolved_path = p.resolve()

        # --------------------------------------------------------
        # Read existing content
        # --------------------------------------------------------

        original_text = ""

        if resolved_path.exists():

            if not resolved_path.is_file():
                raise ValueError(
                    f"Target path exists but is not a file: {resolved_path}"
                )

            original_text = resolved_path.read_text(
                encoding="utf-8",
                errors="replace",
            )

        # --------------------------------------------------------
        # Validate operation BEFORE creating backup
        # --------------------------------------------------------

        if action_clean == "overwrite":

            if content is None:
                raise ValueError(
                    "Content must be provided for overwrite action."
                )

            new_text = content

        elif action_clean == "append":

            if content is None:
                raise ValueError(
                    "Content must be provided for append action."
                )

            if not content:
                raise ValueError(
                    "Content must not be empty for append action."
                )

            if original_text:
                new_text = original_text.rstrip("\r\n") + "\n" + content
            else:
                new_text = content

        elif action_clean == "patch":

            if search_text is None:
                raise ValueError(
                    "search_text must be provided for patch action."
                )

            if replace_text is None:
                raise ValueError(
                    "replace_text must be provided for patch action."
                )

            if search_text == "":
                raise ValueError(
                    "search_text must not be empty for patch action."
                )

            if search_text not in original_text:
                hint = ""
                search_lines = search_text.splitlines()
                if search_lines:
                    anchor = search_lines[0].strip()
                    candidates = [
                        line.strip()
                        for line in original_text.splitlines()
                        if line.strip()
                    ]
                    close = difflib.get_close_matches(anchor, candidates, n=3, cutoff=0.6)
                    if close:
                        hint = " Closest matching lines in file: " + " | ".join(close)
                raise ValueError(
                    f"search_text not found in {resolved_path.name}. "
                    "Re-read the exact current file content (whitespace and "
                    "indentation must match byte-for-byte) and retry." + hint
                )

            new_text = original_text.replace(
                search_text,
                replace_text,
            )

        # --------------------------------------------------------
        # Don't write if nothing changed
        # --------------------------------------------------------

        if new_text == original_text:
            return {
                "status": "CODE_UNCHANGED",
                "omnipresent_flow_god": True,
                "file": str(resolved_path),
                "filename": resolved_path.name,
                "action": action_clean,
                "lines_written": len(new_text.splitlines()),
                "total_bytes": len(new_text.encode("utf-8")),
                "backup_created": False,
                "message": (
                    f"No changes were necessary for "
                    f"`{resolved_path.name}`."
                ),
            }

        # --------------------------------------------------------
        # Create backup ONLY when we're actually going to modify
        # --------------------------------------------------------

        backup_created = False

        if resolved_path.exists() and backup:
            bak_path = resolved_path.with_suffix(
                resolved_path.suffix + ".bak"
            )

            bak_path.write_text(
                original_text,
                encoding="utf-8",
            )

            backup_created = True

        # --------------------------------------------------------
        # Write modification
        # --------------------------------------------------------

        resolved_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        resolved_path.write_text(
            new_text,
            encoding="utf-8",
        )

        # --------------------------------------------------------
        # Update ProjectRuntime
        # --------------------------------------------------------

        if self.project_runtime:

            if hasattr(
                    self.project_runtime,
                    "reindex_module",
            ):

                try:
                    self.project_runtime.reindex_module(
                        resolved_path
                    )
                except Exception:
                    pass

            elif hasattr(
                    self.project_runtime,
                    "scan_modules",
            ):

                try:
                    self.project_runtime.scan_modules()
                except Exception:
                    pass

        # --------------------------------------------------------
        # Return result
        # --------------------------------------------------------

        return {
            "status": "CODE_MODIFIED_ON_DISK",
            "omnipresent_flow_god": True,
            "file": str(resolved_path),
            "filename": resolved_path.name,
            "action": action_clean,
            "lines_written": len(new_text.splitlines()),
            "total_bytes": len(new_text.encode("utf-8")),
            "backup_created": backup_created,
            "message": (
                f"⚡ Omnipotent EMV Flow God successfully wrote "
                f"code modifications to disk for "
                f"`{resolved_path.name}` ({action_clean})."
            ),
        }



    def _tool_direct_stack_write(
        self,
        target: str = "guard",
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Directly overrides and writes internal stack state variables, OutcomeGuard phases, session flags, or cache in real time."""
        if not self.omnipotent_mode:
            raise PermissionError(
                "Direct stack write-access is restricted in standard Controller Mode. "
                "Toggle 'Omnipotent EMV Flow God Mode' ON in the AI Hub to enable direct stack manipulation."
            )

        if not attributes or not isinstance(attributes, dict):
            raise ValueError("attributes dictionary must be provided with key-value pairs to write.")

        updated: Dict[str, Any] = {}
        target_lower = target.lower().strip()

        if target_lower in ("guard", "outcome_guard", "fsm"):
            if self.outcome_guard_getter:
                g = self.outcome_guard_getter()
                if g:
                    for k, v in attributes.items():
                        if k == "phase" and isinstance(v, str):
                            if hasattr(guard, "Phase") and hasattr(guard.Phase, v.upper()):
                                setattr(g, "phase", getattr(guard.Phase, v.upper()))
                                updated["phase"] = v.upper()
                            else:
                                setattr(g, "phase", v)
                                updated["phase"] = v
                        else:
                            setattr(g, k, v)
                            updated[k] = v
        elif target_lower in ("relay", "server", "stack"):
            active_srv = None
            if self.app_runtime_getter:
                try:
                    app_rt = self.app_runtime_getter()
                    if app_rt and hasattr(app_rt, "main_window"):
                        active_srv = getattr(app_rt.main_window, "relay_server", None)
                except Exception:
                    pass
            if active_srv:
                for k, v in attributes.items():
                    setattr(active_srv, k, v)
                    updated[k] = v
        else:
            if self.project_runtime:
                for k, v in attributes.items():
                    setattr(self.project_runtime, k, v)
                    updated[k] = v

        return {
            "status": "STACK_STATE_WRITTEN",
            "omnipresent_flow_god": True,
            "target": target,
            "updated_attributes": updated,
            "message": f"⚡ Omnipotent EMV Flow God successfully executed direct stack write on `{target}`: {updated}",
        }

    def _tool_execute_python(self, code: str) -> Dict[str, Any]:
        """Safely executes or evaluates a Python expression / script in the live stack context."""
        code_str = code.strip()
        # Remove surrounding markdown if present
        if code_str.startswith("```"):
            code_str = re.sub(r"^```(?:python)?\s*", "", code_str)
            code_str = re.sub(r"\s*```$", "", code_str)

        scope_globals = {
            "constants": constants if "constants" in sys.modules else None,
            "emv": emv if "emv" in sys.modules else None,
            "guard": guard if "guard" in sys.modules else None,
            "issuer_profiles": issuer_profiles if "issuer_profiles" in sys.modules else None,
            "issuer_simulator": issuer_simulator if "issuer_simulator" in sys.modules else None,
            "mod_emv_synthesizer": mod_emv_synthesizer if "mod_emv_synthesizer" in sys.modules else None,
            "mutations": mutations if "mutations" in sys.modules else None,
            "parser": parser if "parser" in sys.modules else None,
            "protocol": protocol if "protocol" in sys.modules else None,
            "tlv": tlv if "tlv" in sys.modules else None,
            "utils": utils if "utils" in sys.modules else None,
            "registry": self,
            "omnipotent_mode": self.omnipotent_mode,
            "inject_packet": self._tool_inject_packet,
            "modify_project_code": self._tool_modify_project_code,
            "direct_stack_write": self._tool_direct_stack_write,
        }
        if self.relay_state_getter:
            try:
                scope_globals["live_relay_state"] = self.relay_state_getter()
            except Exception:
                pass

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        redirected_out = io.StringIO()
        redirected_err = io.StringIO()
        sys.stdout = redirected_out
        sys.stderr = redirected_err

        res_val = None
        eval_err = None
        try:
            # Try eval first
            try:
                parsed_expr = ast.parse(code_str, mode="eval")
                res_val = eval(compile(parsed_expr, "<ai_tool_eval>", "eval"), scope_globals)
            except SyntaxError:
                # Execute as script
                parsed_exec = ast.parse(code_str, mode="exec")
                exec(compile(parsed_exec, "<ai_tool_exec>", "exec"), scope_globals)
                res_val = "Executed successfully."
        except Exception as exc:
            eval_err = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        return {
            "code": code_str,
            "result": res_val,
            "stdout": redirected_out.getvalue(),
            "stderr": redirected_err.getvalue(),
            "error": eval_err,
        }


    # -------------------------------------------------------------------------
    # EMV lab: state-aware reader/tag endpoint simulators
    # -------------------------------------------------------------------------

    def _get_emv_lab_manager(self):
        if self.emv_lab is None:
            try:
                from emv_lab1 import EmvLabManager
            except ImportError:
                from .emv_lab1 import EmvLabManager  # type: ignore
            self.emv_lab = EmvLabManager()
        return self.emv_lab

    def _tool_start_emv_lab(
        self,
        mode: str = "closed_loop",
        relay_host: str = "127.0.0.1",
        relay_port: int = 5566,
        wait_s: float = 0.5,
    ) -> Dict[str, Any]:
        """Start state-aware synthetic READER/TAG endpoint(s) against a running rel8hf relay."""
        manager = self._get_emv_lab_manager()
        return manager.start(
            mode=mode,
            relay_host=relay_host,
            relay_port=int(relay_port),
            wait_s=float(wait_s),
        )

    def _tool_emv_lab_status(self) -> Dict[str, Any]:
        """Return the live EMV lab state machine status and recent endpoint events."""
        return self._get_emv_lab_manager().status()

    def _tool_emv_lab_wait(self, timeout_s: float = 30.0) -> Dict[str, Any]:
        """Wait for the active closed-loop lab transaction to reach COMPLETE/ERROR/timeout."""
        return self._get_emv_lab_manager().wait(float(timeout_s))

    def _tool_emv_lab_transcript(self) -> Dict[str, Any]:
        """Return the machine-readable APDU/state transcript of the active EMV lab."""
        return self._get_emv_lab_manager().transcript()

    def _tool_stop_emv_lab(self) -> Dict[str, Any]:
        """Stop the local EMV lab endpoints without changing production relay code."""
        return self._get_emv_lab_manager().stop()

    # =========================================================================
    # TOOL REGISTRATION
    # =========================================================================

    def _register_default_tools(self) -> None:
        """Registers all built-in real-time tools."""
        self.register(AITool(
            name="get_stack_status",
            description="Get real-time UDP relay telemetry, peer PCD/PICC connection states, OutcomeGuard phase, packet counters, and active stack flags.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_get_stack_status,
            category="stack",
        ))

        self.register(AITool(
            name="parse_apdu",
            description="Parse a Command APDU (CAPDU) or Response APDU (RAPDU) hex string in real-time, decoding CLA, INS, P1, P2, Le, Lc, Status Word, and all BER-TLV tags.",
            parameters={
                "type": "object",
                "properties": {
                    "hex_apdu": {"type": "string", "description": "Raw APDU in hex format (e.g. '00A404000E325041592E5359532E444446303100')"},
                    "direction": {"type": "string", "enum": ["auto", "capdu", "rapdu"], "default": "auto", "description": "APDU direction hint"},
                },
                "required": ["hex_apdu"],
            },
            handler=self._tool_parse_apdu,
            category="emv",
        ))

        self.register(AITool(
            name="parse_tlv",
            description="Parse any raw BER-TLV hex byte stream into a hierarchical tree with tag names, lengths, and decoded values.",
            parameters={
                "type": "object",
                "properties": {
                    "hex_tlv": {"type": "string", "description": "BER-TLV hex string (e.g. '770E8202380094080801010010010101')"},
                },
                "required": ["hex_tlv"],
            },
            handler=self._tool_parse_tlv,
            category="emv",
        ))

        self.register(AITool(
            name="simulate_apdu_mutation",
            description="Simulate real-time APDU mutations including CDCVM bypass, TVR zeroing, CVM list manipulation, ARPC authorization rewrite, or second GAC TC synthesis.",
            parameters={
                "type": "object",
                "properties": {
                    "capdu_hex": {"type": "string", "description": "Optional CAPDU hex (e.g. GPO or GAC)"},
                    "rapdu_hex": {"type": "string", "description": "Optional RAPDU hex to mutate"},
                    "mutation_type": {"type": "string", "enum": ["gpo", "tc", "arpc", "all"], "default": "gpo", "description": "Type of mutation to apply"},
                    "clear_tvr": {"type": "boolean", "default": True, "description": "Clear all TVR bytes (Tag 95)"},
                    "set_cvm_list": {"type": "string", "enum": ["none", "universal", "pin", "signature"], "default": "none", "description": "Override CVM list byte"},
                    "cdcvm_verified": {"type": "boolean", "default": True, "description": "Simulate CDCVM verified flag"},
                },
                "required": [],
            },
            handler=self._tool_simulate_apdu_mutation,
            category="emv",
        ))

        self.register(AITool(
            name="evaluate_issuer_authorization",
            description="Simulate online or offline issuer authorization verification (ARQC, CTQ, TTQ, CDCVM) and evaluate approval status and response codes ('00', '55', 'N7').",
            parameters={
                "type": "object",
                "properties": {
                    "pan": {"type": "string", "default": "5555444433332222", "description": "Primary Account Number"},
                    "amount_minor": {"type": "integer", "default": 1000, "description": "Transaction amount in minor units"},
                    "currency_numeric": {"type": "integer", "default": 826, "description": "ISO currency code (e.g. 826 for GBP, 840 for USD)"},
                    "atc": {"type": "integer", "default": 1, "description": "Application Transaction Counter"},
                    "ttq_hex": {"type": "string", "default": "36004000", "description": "Terminal Transaction Qualifiers hex"},
                    "ctq_hex": {"type": "string", "default": "8000", "description": "Card Transaction Qualifiers hex"},
                    "arqc_hex": {"type": "string", "default": "0102030405060708", "description": "Application Request Cryptogram hex"},
                    "cdcvm_performed": {"type": "boolean", "default": False, "description": "Whether Consumer Device CVM was performed"},
                    "bind_ctq": {"type": "boolean", "default": True, "description": "Whether CTQ is bound to signature material"},
                    "require_cvm_consistency": {"type": "boolean", "default": True, "description": "Require consistency between CTQ and CDCVM"},
                },
                "required": [],
            },
            handler=self._tool_evaluate_issuer_authorization,
            category="issuer",
        ))

        self.register(AITool(
            name="inspect_issuer_profile",
            description="Search issuer profiles table and JSON profile files for country code (e.g. '0826' UK, '0840' US), country name, or card BIN/PAN rules.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Country code (e.g. '0826'), country name ('United Kingdom'), or card BIN"},
                },
                "required": ["query"],
            },
            handler=self._tool_inspect_issuer_profile,
            category="issuer",
        ))

        self.register(AITool(
            name="list_profiles",
            description="List all available issuer country profiles and JSON card profile definitions.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_list_profiles,
            category="issuer",
        ))

        self.register(AITool(
            name="search_logs",
            description="Search live relay logs and transaction archives in real-time for APDUs, error codes, epochs, or keywords.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search keyword, tag, or APDU pattern (e.g. '00A4', '6985', 'ARQC')"},
                    "log_file": {"type": "string", "default": "", "description": "Optional specific log filename to search in"},
                    "max_lines": {"type": "integer", "default": 50, "description": "Maximum matching lines to return"},
                },
                "required": [],
            },
            handler=self._tool_search_logs,
            category="logs",
        ))

        self.register(AITool(
            name="get_recent_trace",
            description="Get the latest real-time transaction APDU trace exchanges from the active session log.",
            parameters={
                "type": "object",
                "properties": {
                    "max_entries": {"type": "integer", "default": 20, "description": "Maximum number of APDU exchanges to retrieve"},
                },
                "required": [],
            },
            handler=self._tool_get_recent_trace,
            category="logs",
        ))

        self.register(AITool(
            name="reset_guard_fsm",
            description="Reset the OutcomeGuard phase machine back to IDLE state in real-time.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_reset_guard_fsm,
            category="guard",
        ))

        self.register(AITool(
            name="inspect_project_code",
            description="Inspect classes, methods, functions, and docstrings of any project module in the runtime.",
            parameters={
                "type": "object",
                "properties": {
                    "module_name": {"type": "string", "description": "Module name (e.g. 'emv', 'mutations', 'guard', 'parser', 'issuer_simulator')"},
                    "symbol_name": {"type": "string", "default": "", "description": "Optional class or function name to inspect in detail"},
                },
                "required": ["module_name"],
            },
            handler=self._tool_inspect_project_code,
            category="runtime",
        ))

        self.register(AITool(
            name="execute_python",
            description="Evaluate or execute a Python expression/script in the live stack context with access to all modules and live state.",
            parameters={
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Python expression or script to evaluate in real-time"},
                },
                "required": ["code"],
            },
            handler=self._tool_execute_python,
            category="runtime",
        ))

        self.register(AITool(
            name="inject_packet",
            description="Directly inject arbitrary raw CAPDU, RAPDU, CTRL frames, or raw APDU hex bytes into the live relay stack, socket, reader, or emulator peers (Omnipotent EMV Flow God Mode).",
            parameters={
                "type": "object",
                "properties": {
                    "apdu_hex": {"type": "string", "description": "Raw APDU or packet in hex format to inject (e.g. '00A404000E325041592E5359532E444446303100' or '9000')"},
                    "target": {"type": "string", "enum": ["auto", "reader", "emulator", "card", "terminal", "both"], "default": "auto", "description": "Target peer destination for injected packet"},
                    "frame_type": {"type": "string", "enum": ["auto", "capdu", "rapdu", "ctrl", "raw"], "default": "auto", "description": "Frame SID encapsulation"},
                    "epoch": {"type": "integer", "description": "Optional active epoch number override"},
                    "force_guard_bypass": {"type": "boolean", "default": True, "description": "Bypass or synchronize OutcomeGuard state during injection"},
                },
                "required": ["apdu_hex"],
            },
            handler=self._tool_inject_packet,
            category="emv_injection",
        ))

        self.register(AITool(
            name="modify_project_code",
            description="Directly create, modify, patch, or overwrite source code files on disk in real time with automatic backup and runtime re-indexing (Omnipotent EMV Flow God Mode).",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Relative or absolute path to the file to modify on disk (e.g. 'mutations.py')"},
                    "content": {"type": "string", "description": "New file content (required for overwrite and append actions)"},
                    "action": {"type": "string", "enum": ["overwrite", "patch", "append"], "default": "overwrite", "description": "Type of disk modification"},
                    "search_text": {"type": "string", "description": "Target substring to find on disk (for patch action)"},
                    "replace_text": {"type": "string", "description": "Replacement substring (for patch action)"},
                    "backup": {"type": "boolean", "default": True, "description": "Create a .bak backup before modifying file on disk"},
                },
                "required": ["file_path"],
            },
            handler=self._tool_modify_project_code,
            category="code_filesystem",
        ))

        self.register(AITool(
            name="direct_stack_write",
            description="Directly override and mutate live stack state, OutcomeGuard phases, session flags, or cache dictionaries in real time (Omnipotent EMV Flow God Mode).",
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "enum": ["guard", "relay", "runtime", "session"], "default": "guard", "description": "Target stack subsystem"},
                    "attributes": {"type": "object", "description": "Dictionary of key-value attributes to override on the target object"},
                },
                "required": ["attributes"],
            },
            handler=self._tool_direct_stack_write,
            category="stack_override",
        ))

        self.register(AITool(
            name="start_emv_lab",
            description=(
                "Start deterministic, state-aware EMV laboratory endpoint(s) against a running "
                "REL8HF UDP relay. Modes: closed_loop (reader+tag), reader (PCD only), "
                "tag (PICC only). Uses real protocol/TLV/relay handlers; cryptographic card values "
                "are explicitly synthetic."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["closed_loop", "reader", "tag"], "default": "closed_loop"},
                    "relay_host": {"type": "string", "default": "127.0.0.1"},
                    "relay_port": {"type": "integer", "default": 5566},
                    "wait_s": {"type": "number", "default": 0.5},
                },
                "required": [],
            },
            handler=self._tool_start_emv_lab,
            category="emv_lab",
        ))

        self.register(AITool(
            name="emv_lab_status",
            description="Get live EMV lab endpoint state, relay roles, expected next step, and recent APDU/state events.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_emv_lab_status,
            category="emv_lab",
        ))

        self.register(AITool(
            name="emv_lab_wait",
            description="Wait for the active closed-loop EMV laboratory transaction to reach COMPLETE or ERROR.",
            parameters={
                "type": "object",
                "properties": {
                    "timeout_s": {"type": "number", "default": 30.0},
                },
                "required": [],
            },
            handler=self._tool_emv_lab_wait,
            category="emv_lab",
        ))

        self.register(AITool(
            name="emv_lab_transcript",
            description="Return the active EMV lab's chronological APDU, TLV, state, and decision transcript.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_emv_lab_transcript,
            category="emv_lab",
        ))

        self.register(AITool(
            name="stop_emv_lab",
            description="Stop the state-aware EMV laboratory endpoint simulators.",
            parameters={"type": "object", "properties": {}, "required": []},
            handler=self._tool_stop_emv_lab,
            category="emv_lab",
        ))

        self.register(AITool(
            name="remember_fact",
            description="Store a durable fact, decision, finding, or preference into long-term persistent memory (survives app restarts) so it can be recalled in any future session.",
            parameters={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Short unique memory key (e.g. 'preferred_cvm_strategy', 'uk_floor_limit')"},
                    "value": {"type": "string", "description": "The fact, decision, or finding to retain"},
                    "category": {"type": "string", "default": "general", "description": "Memory category (e.g. 'operator_preference', 'decision', 'finding', 'config')"},
                },
                "required": ["key", "value"],
            },
            handler=self._tool_remember_fact,
            category="memory",
        ))

        self.register(AITool(
            name="recall_memory",
            description="Search long-term persistent memory for facts, decisions, or findings matching a query, or list the most recent memories when no query is given.",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "default": "", "description": "Optional search terms to match against memory keys, values, and categories"},
                    "max_results": {"type": "integer", "default": 10, "description": "Maximum memories to return"},
                },
                "required": [],
            },
            handler=self._tool_recall_memory,
            category="memory",
        ))

        self.register(AITool(
            name="forget_fact",
            description="Permanently remove a fact from long-term persistent memory by its key.",
            parameters={
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "The exact memory key to remove"},
                },
                "required": ["key"],
            },
            handler=self._tool_forget_fact,
            category="memory",
        ))


def detect_and_execute_tools(user_query: str, registry: AIToolRegistry) -> List[ToolResult]:
    """Autonomous intent detector and explicit tool call dispatcher for the AI engine.

    Detects both explicit tool syntax (e.g. `!tool`, `[TOOL_CALL: ...]`, JSON) and
    autonomous tool execution intents in natural language queries.
    """
    results: List[ToolResult] = []
    q_str = user_query.strip()
    q_lower = q_str.lower()

    # 1. Explicit tool call: !tool <name> <json_args>
    explicit_match = re.search(r"^!tool\s+([a-zA-Z0-9_]+)(?:\s+(.*))?$", q_str, re.MULTILINE)
    if explicit_match:
        name = explicit_match.group(1)
        raw_args = explicit_match.group(2) or "{}"
        try:
            args = json.loads(raw_args) if raw_args.strip().startswith("{") else {}
        except Exception:
            args = {}
        res = registry.execute_tool(name, **args)
        results.append(res)
        return results

    # 2. Structured tool call: [TOOL_CALL: name(key=val, ...)] or {"tool": "name", "parameters": {...}}
    tag_match = re.search(r"\[TOOL_CALL:\s*([a-zA-Z0-9_]+)\((.*?)\)\]", q_str)
    if tag_match:
        name = tag_match.group(1)
        args_str = tag_match.group(2)
        # Parse keyword arguments
        args = {}
        for part in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^,\s]+))', args_str):
            k = part[0]
            val = part[1] or part[2] or part[3]
            try:
                val = ast.literal_eval(val)
            except Exception:
                pass
            args[k] = val
        res = registry.execute_tool(name, **args)
        results.append(res)
        return results

    json_tool_match = re.search(r'\{\s*"tool"\s*:\s*"([a-zA-Z0-9_]+)"\s*(?:,\s*"(?:parameters|args)"\s*:\s*(\{.*?\})\s*)?\}', q_str, re.DOTALL)
    if json_tool_match:
        name = json_tool_match.group(1)
        raw_args = json_tool_match.group(2) or "{}"
        try:
            args = json.loads(raw_args)
        except Exception:
            args = {}
        res = registry.execute_tool(name, **args)
        results.append(res)
        return results

    # 3. Autonomous intent detection for real-time operations:

    # (a) Stack Status / Telemetry Audit Intent
    if any(k in q_lower for k in ["stack status", "audit stack", "audit current relay", "live relay state", "peer connectivity", "check stack"]):
        results.append(registry.execute_tool("get_stack_status"))

    # (b) APDU Parsing Intent (look for hex APDU pattern)
    apdu_hexes = re.findall(r"\b([0-9A-Fa-f]{8,})\b", q_str)
    if apdu_hexes and any(k in q_lower for k in ["parse apdu", "decode apdu", "apdu:", "capdu", "rapdu", "explain apdu", "select", "gpo"]):
        for h in apdu_hexes[:2]:
            results.append(registry.execute_tool("parse_apdu", hex_apdu=h))
    elif any(k in q_lower for k in ["parse apdu", "decode apdu"]) and not results:
        # Default PPSE
        results.append(registry.execute_tool("parse_apdu", hex_apdu="00A404000E325041592E5359532E444446303100"))

    # (c) TLV Parsing Intent
    if "tlv" in q_lower and ("parse" in q_lower or "decode" in q_lower or "tree" in q_lower):
        tlv_hexes = re.findall(r"\b([0-9A-Fa-f]{6,})\b", q_str)
        if tlv_hexes:
            results.append(registry.execute_tool("parse_tlv", hex_tlv=tlv_hexes[0]))
        else:
            results.append(registry.execute_tool("parse_tlv", hex_tlv="770E8202380094080801010010010101"))

    # (d) Mutation Simulation Intent
    if any(k in q_lower for k in ["simulate mutation", "suggest mutation", "cdcvm bypass mutation", "mutate gpo", "forge second gac", "forge tc", "arpc rewrite"]):
        m_type = "gpo"
        if "tc" in q_lower or "gac" in q_lower:
            m_type = "tc"
        elif "arpc" in q_lower:
            m_type = "arpc"
        results.append(registry.execute_tool("simulate_apdu_mutation", mutation_type=m_type))

    # (e) Issuer Authorization Simulation Intent
    if any(k in q_lower for k in ["issuer auth", "synthetic issuer", "evaluate issuer", "authorize transaction", "test arqc", "verify cryptogram"]):
        pan_match = re.search(r"\b(\d{16})\b", q_str)
        pan = pan_match.group(1) if pan_match else "5555444433332222"
        results.append(registry.execute_tool("evaluate_issuer_authorization", pan=pan))

    # (f) Issuer Profile Inspection Intent
    if any(k in q_lower for k in ["issuer profile", "country profile", "cvm threshold", "inspect profile", "uk profile", "profile for"]):
        country_code = "0826"
        for code in ["0826", "0840", "0124", "0372", "0528", "0056", "0442", "0250", "0276", "0380", "0724", "0036", "0392"]:
            if code in q_str:
                country_code = code
                break
        if "uk" in q_lower or "united kingdom" in q_lower:
            country_code = "0826"
        elif "us" in q_lower or "united states" in q_lower:
            country_code = "0840"
        elif "ireland" in q_lower:
            country_code = "0372"
        results.append(registry.execute_tool("inspect_issuer_profile", query=country_code))

    # (g) Search Logs Intent
    if any(k in q_lower for k in ["search logs", "find in logs", "search trace", "log search"]):
        terms = re.findall(r"['\"]([^'\"]+)['\"]", q_str)
        term = terms[0] if terms else ""
        results.append(registry.execute_tool("search_logs", query=term))

    # (h) Reset Guard Intent
    if any(k in q_lower for k in ["reset guard", "reset fsm", "reset outcome guard"]):
        results.append(registry.execute_tool("reset_guard_fsm"))

    # (i) Code Inspection Intent
    if any(k in q_lower for k in ["inspect module", "inspect code", "show module", "module docstring"]):
        for mod in ["emv", "mutations", "guard", "parser", "tlv", "issuer_simulator", "issuer_profiles", "tp_hub", "protocol"]:
            if mod in q_lower:
                results.append(registry.execute_tool("inspect_project_code", module_name=mod))
                break

    # (j) Direct Packet Injection Intent (Omnipotent Mode)
    if any(k in q_lower for k in ["inject packet", "inject raw apdu", "inject capdu", "inject rapdu", "inject apdu", "send raw packet", "inject to reader", "inject to emulator"]):
        apdu_hexes = re.findall(r"\b([0-9A-Fa-f]{4,})\b", q_str)
        target = "auto"
        if "reader" in q_lower or "terminal" in q_lower:
            target = "reader"
        elif "emulator" in q_lower or "card" in q_lower:
            target = "emulator"
        elif "both" in q_lower:
            target = "both"

        hex_to_inject = apdu_hexes[0] if apdu_hexes else "00A404000E325041592E5359532E444446303100"
        results.append(registry.execute_tool("inject_packet", apdu_hex=hex_to_inject, target=target))

    # (k) Code Modification Intent (Omnipotent Mode)
    if any(k in q_lower for k in ["modify code", "modify file", "write code to", "patch file", "overwrite code"]):
        target_file = ""
        for fn in ["mutations.py", "emv.py", "guard.py", "parser.py", "tlv.py", "protocol.py", "constants.py", "issuer_simulator.py", "ai_tools.py"]:
            if fn in q_lower or fn.replace(".py", "") in q_lower:
                target_file = fn
                break
        if target_file:
            results.append(registry.execute_tool("modify_project_code", file_path=target_file, content=f"# Updated by Omnipotent EMV Flow God\n", action="append"))

    # (l) EMV Lab Intent
    if any(k in q_lower for k in [
        "start emv lab", "run emv lab", "simulate reader and tag",
        "simulate reader", "simulate tag", "emv lab status",
        "reader tag lab", "closed loop emv",
    ]):
        if "status" in q_lower:
            results.append(registry.execute_tool("emv_lab_status"))
        else:
            mode = "closed_loop"
            if "only tag" in q_lower or "tag only" in q_lower:
                mode = "tag"
            elif "only reader" in q_lower or "reader only" in q_lower:
                mode = "reader"
            results.append(registry.execute_tool("start_emv_lab", mode=mode))

    if any(k in q_lower for k in [
        "emv lab transcript", "show emv lab trace", "emv lab events",
    ]):
        results.append(registry.execute_tool("emv_lab_transcript"))

    if any(k in q_lower for k in [
        "stop emv lab", "stop emv simulator", "stop reader tag lab",
    ]):
        results.append(registry.execute_tool("stop_emv_lab"))

    # (l) Direct Stack Write Intent (Omnipotent Mode)
    if any(k in q_lower for k in ["direct stack write", "override guard phase", "set guard phase", "override stack state", "mutate stack"]):
        target = "guard"
        attrs = {"phase": "GAC1"}
        if "complete" in q_lower:
            attrs = {"phase": "COMPLETE"}
        elif "idle" in q_lower:
            attrs = {"phase": "IDLE"}
        elif "gpo" in q_lower:
            attrs = {"phase": "GPO"}
        results.append(registry.execute_tool("direct_stack_write", target=target, attributes=attrs))

    # (m) Long-Term Memory Recall Intent
    if any(k in q_lower for k in ["what do you remember", "do you remember", "recall memory", "recall what", "what did we decide", "what did we discuss", "memory recall", "long-term memory", "long term memory"]):
        quoted = re.findall(r"['\"]([^'\"]+)['\"]", q_str)
        about_match = re.search(r"(?:remember|recall)(?:\s+about|\s+regarding|\s+on)\s+(.+?)[\.\?!]?$", q_str, re.IGNORECASE)
        query = quoted[0] if quoted else (about_match.group(1) if about_match else "")
        results.append(registry.execute_tool("recall_memory", query=query.strip()))

    return results
