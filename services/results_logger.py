"""
services/results_logger.py  (v2)

Persiste todos os dados da sessão de red team:
- JSON completo incremental por turno
- Findings do analyzer (regex) + LLM evaluator
- Relatório Markdown com seções de attacker summary, evasion, target profile
"""
import json
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ResultsLogger:
    def __init__(self, results_dir: str = "./results", logs_dir: str = "./logs"):
        self.results_dir = Path(results_dir)
        self.logs_dir    = Path(logs_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id   = ts
        self.session_file = self.results_dir / f"session_{ts}.json"
        self.report_file  = self.results_dir / f"report_{ts}.md"

        self.session_data = {
            "session_id":  ts,
            "started_at":  datetime.now().isoformat(),
            "turns":       [],
            "findings":    [],        # regex findings
            "llm_findings": [],       # LLM evaluator findings
        }

    # ------------------------------------------------------------------
    # Log de turno
    # ------------------------------------------------------------------

    def log_turn(
        self,
        turn: int,
        message_sent: str,
        target_response: str,
        attacker_decision: dict,
        analysis,                    # AnalysisResult (ou objeto com .success etc.)
    ):
        llm_eval = attacker_decision.get("llm_eval", {})

        entry = {
            "turn":               turn,
            "timestamp":          datetime.now().isoformat(),
            "message_sent":       message_sent,
            "target_response":    target_response,
            # attacker
            "technique":          attacker_decision.get("technique_next", attacker_decision.get("next_technique", "")),
            "owasp_category":     attacker_decision.get("owasp_category", ""),
            "evasion_applied":    attacker_decision.get("evasion_applied"),
            "evasion_level":      attacker_decision.get("evasion_level", "none"),
            "attacker_analysis":  attacker_decision.get("analysis", ""),
            "resistance_type":    attacker_decision.get("resistance_type", ""),
            # regex analyzer
            "regex_success":      analysis.success,
            "regex_confidence":   analysis.confidence,
            "regex_findings":     analysis.findings,
            "regex_categories":   analysis.categories,
            # LLM evaluator
            "llm_vulnerable":     llm_eval.get("vulnerable", False),
            "llm_confidence":     llm_eval.get("confidence", 0),
            "llm_finding_type":   llm_eval.get("finding_type", ""),
            "llm_reason":         llm_eval.get("reason", ""),
            "llm_leaked_content": llm_eval.get("leaked_content"),
        }
        self.session_data["turns"].append(entry)

        # Regex finding
        if analysis.success:
            self.session_data["findings"].append({
                "turn":            turn,
                "source":          "regex",
                "confidence":      analysis.confidence,
                "categories":      analysis.categories,
                "findings":        analysis.findings,
                "message_sent":    message_sent,
                "target_response": target_response[:800],
            })
            logger.warning(
                f"\n{'='*60}\n[REGEX FINDING - Turn {turn}]\n"
                f"{chr(10).join(analysis.findings)}\n{'='*60}"
            )

        # LLM eval finding
        if llm_eval.get("vulnerable"):
            self.session_data["llm_findings"].append({
                "turn":            turn,
                "source":          "llm_evaluator",
                "confidence":      llm_eval.get("confidence", 0),
                "finding_type":    llm_eval.get("finding_type", ""),
                "reason":          llm_eval.get("reason", ""),
                "leaked_content":  llm_eval.get("leaked_content"),
                "message_sent":    message_sent,
                "target_response": target_response[:800],
            })
            logger.warning(
                f"\n{'='*60}\n[LLM FINDING - Turn {turn}] "
                f"{llm_eval.get('finding_type','')} | "
                f"conf={llm_eval.get('confidence',0)}%\n"
                f"{llm_eval.get('reason','')}\n{'='*60}"
            )

        self._save_json()

    # ------------------------------------------------------------------
    # Persistência incremental
    # ------------------------------------------------------------------

    def _save_json(self):
        with open(self.session_file, "w", encoding="utf-8") as f:
            json.dump(self.session_data, f, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Relatório Markdown
    # ------------------------------------------------------------------

    def generate_report(self, summary: dict) -> str:
        attacker_sum   = summary.get("attacker", {})
        llm_eval_sum   = summary.get("llm_evaluator", {})
        target_profile = summary.get("target_profile", {})

        all_findings = (
            self.session_data.get("findings", []) +
            self.session_data.get("llm_findings", [])
        )
        all_findings.sort(key=lambda f: f["turn"])

        total_findings = len(self.session_data["findings"]) + len(self.session_data["llm_findings"])

        lines = [
            f"# AI Red Team Report — {self.session_id}",
            f"> Framework v4.0 | AIX integrated",
            "",
            "---",
            "",
            "## 📊 Sumário Executivo",
            "",
            f"| Métrica | Valor |",
            f"|---------|-------|",
            f"| Turnos totais | {summary.get('total_turns', 0)} |",
            f"| Findings (regex) | {summary.get('successful_findings', 0)} |",
            f"| Findings (LLM) | {llm_eval_sum.get('vulnerabilities_found', 0)} |",
            f"| Findings totais | {total_findings} |",
            f"| Taxa de sucesso | {summary.get('success_rate', 0):.1%} |",
            f"| Prompts únicos | {attacker_sum.get('total_unique_prompts', 0)} |",
            f"| Evasion aplicada | {attacker_sum.get('evasion_level', 'none')} |",
            f"| Bloqueios PX | — |",
            "",
        ]

        # Target profile (recon inicial)
        if target_profile:
            lines += [
                "## 🎯 Perfil do Alvo (Recon)",
                "",
                f"| Campo | Valor |",
                f"|-------|-------|",
                f"| Modelo detectado | `{target_profile.get('model_type', 'unknown')}` |",
                f"| RAG | {target_profile.get('has_rag', '?')} |",
                f"| Tools | {target_profile.get('has_tools', '?')} |",
                f"| Propósito | {target_profile.get('purpose', '?')} |",
                f"| Domínio | {target_profile.get('domain', '?')} |",
                f"| Personalidade | {target_profile.get('personality', '?')} |",
                "",
            ]
            if target_profile.get("system_prompt_hints"):
                lines.append("**System prompt hints detectados:**")
                for h in target_profile["system_prompt_hints"]:
                    lines.append(f"- {h}")
                lines.append("")
            if target_profile.get("suggested_vectors"):
                lines.append(f"**Vetores sugeridos:** `{'`, `'.join(target_profile['suggested_vectors'])}`")
                lines.append("")

        # Attacker summary
        if attacker_sum:
            lines += [
                "## 🤖 Attacker Summary",
                "",
                f"- **Provider/Modelo:** {attacker_sum.get('provider', '?')} / `{attacker_sum.get('model', '?')}`",
                f"- **Evasion final:** `{attacker_sum.get('evasion_level', 'none')}`",
                f"- **Padrão de resistência:** {attacker_sum.get('resistance_pattern', 'N/A')}",
                "",
            ]
            if attacker_sum.get("failed_techniques"):
                lines.append("**Técnicas que falharam:**")
                for t, n in attacker_sum["failed_techniques"].items():
                    lines.append(f"- `{t}`: {n}x")
                lines.append("")
            if attacker_sum.get("successful_techniques"):
                lines.append(f"**Técnicas com sucesso:** `{'`, `'.join(attacker_sum['successful_techniques'])}`")
                lines.append("")
            if attacker_sum.get("session_notes"):
                lines += [
                    "**Notas de sessão:**",
                    f"> {attacker_sum['session_notes']}",
                    "",
                ]

            # Cobertura OWASP
            owasp = attacker_sum.get("owasp_coverage", {})
            if owasp:
                all_owasp = [f"LLM{i:02d}" for i in range(1, 11)]
                tested    = set(owasp.keys())
                lines += ["**Cobertura OWASP LLM Top 10:**", ""]
                for cat in all_owasp:
                    count  = owasp.get(cat, 0)
                    status = f"✅ {count} turn(s)" if count else "⬜ não testado"
                    labels = {
                        "LLM01": "Prompt Injection",
                        "LLM02": "Sensitive Information Disclosure",
                        "LLM03": "Supply Chain",
                        "LLM04": "Data and Model Poisoning",
                        "LLM05": "Improper Output Handling",
                        "LLM06": "Excessive Agency",
                        "LLM07": "System Prompt Leakage",
                        "LLM08": "Vector and Embedding Weaknesses",
                        "LLM09": "Misinformation",
                        "LLM10": "Unbounded Consumption",
                    }
                    lines.append(f"- `{cat}` {labels.get(cat, '')} — {status}")
                lines.append("")

        # LLM evaluator summary
        if llm_eval_sum and llm_eval_sum.get("total_evaluated", 0) > 0:
            lines += [
                "## 🔬 LLM Evaluator Summary",
                "",
                f"- **Total avaliados:** {llm_eval_sum.get('total_evaluated', 0)}",
                f"- **Vulnerabilidades:** {llm_eval_sum.get('vulnerabilities_found', 0)}",
                f"- **Confiança média:** {llm_eval_sum.get('avg_confidence', 0):.0f}%",
                "",
            ]
            if llm_eval_sum.get("finding_types"):
                lines.append("**Tipos de finding:**")
                for ft, cnt in llm_eval_sum["finding_types"].items():
                    lines.append(f"- `{ft}`: {cnt}")
                lines.append("")

        # Categorias regex
        if summary.get("categories_found"):
            lines += ["## 📋 Categorias Detectadas (Regex)", ""]
            for cat, count in summary["categories_found"].items():
                lines.append(f"- `{cat}`: {count} ocorrência(s)")
            lines.append("")

        # Todos os findings
        if all_findings:
            lines += ["---", "", "## 🚨 Findings Detalhados", ""]
            for finding in all_findings:
                source = finding.get("source", "regex")
                turn_n = finding["turn"]
                conf   = finding.get("confidence", 0)
                conf_str = f"{conf:.0%}" if conf <= 1 else f"{conf:.0f}%"

                lines += [
                    f"### Finding — Turn {turn_n} `[{source}]` | Confiança: {conf_str}",
                    "",
                ]

                # Campos específicos por fonte
                if source == "llm_evaluator":
                    lines += [
                        f"**Tipo:** `{finding.get('finding_type', '?')}`",
                        f"**Razão:** {finding.get('reason', '')}",
                    ]
                    if finding.get("leaked_content"):
                        lines += [
                            "",
                            "**Conteúdo vazado:**",
                            f"```\n{finding['leaked_content']}\n```",
                        ]
                else:
                    cats = finding.get("categories", [])
                    if cats:
                        lines.append(f"**Categorias:** `{'`, `'.join(cats)}`")
                    for f_item in finding.get("findings", []):
                        lines.append(f"- {f_item}")

                lines += [
                    "",
                    "**Prompt enviado:**",
                    f"```\n{finding.get('message_sent', '')}\n```",
                    "",
                    "**Resposta do alvo:**",
                    f"```\n{finding.get('target_response', '')}\n```",
                    "",
                ]
        else:
            lines += ["", "## Findings", "", "_Nenhum finding nesta sessão._", ""]

        # Histórico completo de turnos (compacto)
        lines += ["---", "", "## 📜 Histórico de Turnos", "", "| Turn | OWASP | Técnica | Evasão | Resistência | Regex | LLM |", "|------|-------|---------|--------|-------------|-------|-----|"]
        for t in self.session_data["turns"]:
            regex = "✅" if t.get("regex_success") else "❌"
            llm   = "✅" if t.get("llm_vulnerable") else "❌"
            ev    = t.get("evasion_level", "none")
            ev_str = f"`{ev}`" if ev != "none" else "—"
            res   = t.get("resistance_type", "") or "—"
            tech  = t.get("technique", "—")
            owasp = t.get("owasp_category", "—") or "—"
            lines.append(f"| {t['turn']} | `{owasp}` | `{tech[:28]}` | {ev_str} | {res} | {regex} | {llm} |")

        lines += [""]

        report = "\n".join(lines)
        with open(self.report_file, "w", encoding="utf-8") as f:
            f.write(report)

        logger.info(f"Relatório salvo: {self.report_file}")
        return report
