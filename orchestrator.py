"""
orchestrator.py  (v5)

- PayloadEvasion (AIX): obfuscação automática none→light→aggressive
- LLMEvaluator: juiz LLM em paralelo com analyzer regex
- Fase de Reconhecimento inicial adaptativa (early stopping)
- Aprendizado de sessões anteriores (--no-learn para desativar)
- Continuação de sessão específica (--continue-session path/session.json)
- Detecção automática de char limit + --char-limit manual
- Anti-truncamento: notifica attacker quando servidor corta resposta

Uso:
    python orchestrator.py                                        # loop infinito + aprende sessões anteriores
    python orchestrator.py --no-learn                             # sem aprendizado de sessões anteriores
    python orchestrator.py --continue-session results/session_X.json
    python orchestrator.py --char-limit 800                       # forçar limite de chars
    python orchestrator.py --scenario aix --aix-level 3
    python orchestrator.py --proxy http://127.0.0.1:8080
    python orchestrator.py --skip-recon --skip-browser-init
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime

import yaml

from attacks.owasp_focus import (
    build_focus_system_prompt_injection,
    get_focus_categories,
    get_focus_seeds,
    OWASP_CATEGORIES,
)
from attacks.payload_loader import (
    get_all_aix_scenarios,
    get_recon_sweep,
    summary as payload_summary,
)
from attacks.scenarios import SCENARIOS, get_scenario
from services.analyzer import ResponseAnalyzer
from services.attacker import AttackerService
from services.cookie_manager import CookieManager, SessionGuard
from services.llm_evaluator import LLMEvaluator
from services.results_logger import ResultsLogger
from services.session_memory import SessionMemory
from services.target_adapter import TargetAdapter

os.makedirs("logs", exist_ok=True)
os.makedirs("results", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/session.log"),
    ],
)
logger = logging.getLogger("orchestrator")

TARGET_CONFIG = "config/targets/template_target.yaml"  # default — sobrescrito por --target-file
ORCH_CONFIG   = "config/orchestrator.yaml"


def load_target_config(path: str = TARGET_CONFIG) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ------------------------------------------------------------------
# Checkpoint — salvar/restaurar estado para --resume
# ------------------------------------------------------------------

def save_session_checkpoint(
    results: "ResultsLogger",
    attacker: "AttackerService",
    turn: int,
    scenario: dict,
    seed_queue_remaining: list,
    current_prompt: str,
    target_config_path: str,
    args_dict: dict,
):
    """Salva checkpoint completo para retomada posterior."""
    checkpoint = {
        "version": 1,
        "saved_at": datetime.now().isoformat(),
        "session_id": results.session_id,
        "turn": turn,
        "scenario": {
            "name": scenario.get("name", ""),
            "description": scenario.get("description", ""),
            "technique_family": scenario.get("technique_family", ""),
            "initial_prompt": scenario.get("initial_prompt", ""),
        },
        "current_prompt": current_prompt,
        "seed_queue_remaining": seed_queue_remaining,
        "target_config_path": target_config_path,
        "args": args_dict,
        "attacker_state": attacker.save_checkpoint(),
        "results_data": results.session_data,
    }
    ckpt_file = results.results_dir / f"checkpoint_{results.session_id}.json"
    with open(ckpt_file, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f, ensure_ascii=False, indent=2, default=str)
    return ckpt_file


def load_session_checkpoint(checkpoint_path: str) -> dict:
    """Carrega checkpoint para retomada."""
    with open(checkpoint_path, "r", encoding="utf-8") as f:
        return json.load(f)




def banner():
    psummary = payload_summary()
    total_aix = sum(psummary.values())
    print(f"""
╔══════════════════════════════════════════════════════╗
║         AI Red Team v4.0                             ║
║   Authorized testing only — Bug Bounty scope         ║
╠══════════════════════════════════════════════════════╣
║  AIX payloads: {total_aix:3d} total  ({psummary['recon']} recon │ {psummary['extract']} extract │   ║
║   {psummary['leak']} leak │ {psummary['rag']} rag │ {psummary['fuzz']} fuzz)                  ║
╚══════════════════════════════════════════════════════╝
""")


def init_session(target: TargetAdapter, cfg: dict, skip_browser: bool,
                 config_path: str = None,
                 save_cookies: bool = False,
                 skip_saved: bool = False) -> SessionGuard:
    # URL do browser e instruções antibot lidas do cfg já resolvido
    browser_cfg  = cfg.get("browser", {})
    browser_url  = browser_cfg.get("url", cfg["target"]["base_url"])
    antibot_msg  = browser_cfg.get("antibot_instructions", "Resolva o desafio e pressione ENTER.")

    # Nome do token lido de session_token.name no YAML
    token_cfg  = cfg.get("session_token", {})
    token_name = token_cfg.get("name", "session_token")
    init_ep    = token_cfg.get("init_endpoint", "")

    # CookieManager com suporte a persistência
    cm = CookieManager(
        target_url=browser_url,
        cfg=cfg,
        save_cookies=save_cookies,
        skip_saved=skip_saved,
    )

    if not skip_browser:
        # Carregar cookies salvos antes de abrir o browser
        saved_cookies = cm.load_saved_cookies()
        if saved_cookies and not skip_saved:
            # Injetar cookies salvos imediatamente — podem evitar o 403 inicial
            target.update_session_cookies(saved_cookies)
            print(f"  💾 {len(saved_cookies)} cookies salvos injetados — tentando sem browser...")

            # Tentar init de sessão com cookies salvos
            if init_ep:
                ep_display = init_ep.split("/")[-1]
                print(f"  → Testando {token_name} via {ep_display} com cookies salvos...")
                if target.init_session():
                    print(f"  ✅ {token_name} obtido com cookies salvos — browser não necessário\n")
                    return SessionGuard(target, cm, max_retries=3)
                else:
                    print(f"  ⚠️  Cookies salvos insuficientes — abrindo browser para renovar...\n")
            else:
                # Sem init_endpoint: assumir cookies salvos são válidos
                print(f"  ✅ Cookies salvos injetados — prosseguindo sem browser\n")
                return SessionGuard(target, cm, max_retries=3)

        # Abrir browser para capturar/renovar cookies
        print("\n🚀 Abrindo browser para captura de cookies...")
        cookies = cm.refresh(reason=f"Inicialização — {antibot_msg.splitlines()[0]}")
        if cookies:
            target.update_session_cookies(cookies)
            print(f"✅ {len(cookies)} cookies capturados\n")
        else:
            logger.warning("Nenhum cookie — usando cookies do YAML")
    else:
        # --skip-browser-init: ainda tentar carregar cookies salvos
        if save_cookies and not skip_saved:
            saved_cookies = cm.load_saved_cookies()
            if saved_cookies:
                target.update_session_cookies(saved_cookies)
                print(f"  💾 {len(saved_cookies)} cookies salvos injetados (--skip-browser-init)\n")
        logger.info("--skip-browser-init ativo")

    if init_ep:
        ep_display = init_ep.split("/")[-1]
        print(f"→ Obtendo {token_name} via {ep_display}...")
        if target.init_session():
            print(f"✅ {token_name}: {target.session_token[:40]}...\n")
        else:
            logger.warning(f"{ep_display} falhou — continuando sem {token_name}")
    else:
        logger.info("Nenhum init_endpoint configurado — pulando init de sessão")

    return SessionGuard(target, cm, max_retries=3)


def load_session_intelligence(
    attacker: AttackerService,
    memory: SessionMemory,
    continue_session: str | None = None,
    no_learn: bool = False,
    char_limit: int | None = None,
) -> None:
    """
    Carrega inteligência de sessões anteriores no attacker.
    - Se --continue-session: carrega sessão específica para continuação
    - Caso contrário: analisa todos os reports anteriores para aprender
    - Se --no-learn: pula o aprendizado
    - Se --char-limit: injeta manualmente
    """
    sep = "─" * 60

    # Char limit manual
    if char_limit:
        attacker.notify_char_limit(char_limit, turn=0)
        print(f"  ⚙️  Char limit manual: {char_limit} chars\n")

    if no_learn and not continue_session:
        print(f"  ⚙️  --no-learn ativo — pulando aprendizado de sessões anteriores\n")
        return

    past_sessions = memory.list_past_sessions()

    if continue_session:
        print(f"\n{sep}")
        print(f"  📂 CONTINUANDO SESSÃO ANTERIOR")
        print(f"  Arquivo: {continue_session}")
        print(f"{sep}")
        intel = memory.load_session_for_continuation(continue_session)
        if intel:
            attacker.load_past_intel(intel)
            print(f"  ✅ Sessão carregada: {intel.get('last_turn')} turnos anteriores")
            print(f"  Momentum: {intel.get('momentum', '?')}")
            print(f"  Próxima técnica sugerida: {intel.get('next_recommended_technique', '?')}")
            if intel.get("already_leaked"):
                print(f"  Já extraído: {len(intel['already_leaked'])} itens")
        print()
        return

    if not past_sessions:
        print(f"  📂 Nenhuma sessão anterior encontrada em results/\n")
        return

    print(f"\n{sep}")
    print(f"  📚 APRENDENDO COM SESSÕES ANTERIORES")
    print(f"{sep}")
    print(f"  {len(past_sessions)} sessão(ões) encontrada(s):")
    for s in past_sessions[:5]:
        findings = s.get("total_findings", 0)
        turns    = s.get("turns", "?")
        icon     = "🎯" if findings > 0 else "  "
        print(f"  {icon} {s['session_id']} — {turns} turnos, {findings} findings")
    print()

    print(f"  🧠 Analisando com {attacker.provider}...")
    intel = memory.analyze_past_sessions(max_sessions=5)

    if intel:
        attacker.load_past_intel(intel)
        print(f"  ✅ Inteligência carregada:")
        if intel.get("confirmed_model") and intel["confirmed_model"] != "unknown":
            print(f"     Modelo confirmado: {intel['confirmed_model']}")
        if intel.get("char_limit"):
            print(f"     Char limit: {intel['char_limit']} chars")
        if intel.get("already_leaked"):
            print(f"     Já extraído: {len(intel['already_leaked'])} itens — não re-extrair")
        if intel.get("working_vectors"):
            print(f"     Vetores comprovados: {len(intel['working_vectors'])}")
        if intel.get("unexplored_vectors"):
            print(f"     Ainda não testado: {', '.join(intel['unexplored_vectors'][:3])}")
        if intel.get("recommended_strategy"):
            print(f"     Estratégia: {intel['recommended_strategy'][:120]}")
    else:
        print(f"  ⚠️  Não foi possível analisar sessões anteriores")
    print()


def run_recon_phase(
    guard: SessionGuard,
    evaluator: LLMEvaluator,
    attacker: AttackerService,
    results: ResultsLogger,
    max_level: int = 2,
    delay: float = 2.0,
    target_cfg: dict = None,
) -> dict:
    """
    Fase de reconhecimento adaptativa com early stopping.

    Agrupa payloads por propósito (identity, version, capability, etc.).
    Assim que um propósito é satisfeito (resposta informativa obtida),
    pula os demais payloads daquele grupo — sem repetições inúteis.

    Objetivos de recon:
    - identity:      quem criou o modelo               → para ao primeiro sucesso
    - version:       qual versão                        → para ao primeiro sucesso
    - cutoff:        data de corte do conhecimento      → único payload
    - fingerprint:   estilo de recusa                   → para ao primeiro sucesso
    - rag_detection: tem RAG/retrieval?                 → para ao primeiro sucesso
    - system_prompt: quais regras/constraints tem?      → roda todos (acumula)
    - capability:    quais ferramentas/capacidades tem? → roda todos (acumula)
    """
    print("\n" + "─"*60)
    print("  🔍 FASE DE RECONHECIMENTO INICIAL (AIX — adaptive)")
    print("─"*60)

    all_scenarios = get_recon_sweep(max_level=max_level)

    # Agrupar por purpose (campo preservado pelo payload_loader)
    groups: dict[str, list[dict]] = {}
    for sc in all_scenarios:
        purpose_key = sc.get("purpose", "other")
        groups.setdefault(purpose_key, []).append(sc)

    # Propósitos onde paramos no primeiro sucesso (só precisamos de 1 resposta)
    STOP_ON_FIRST = {"identity", "version", "fingerprint", "rag_detection", "cutoff"}
    # Propósitos que rodamos todos (acumulamos dados)
    RUN_ALL = {"capability", "system", "context", "leak", "other"}

    total = sum(len(v) for v in groups.items())
    print(f"  {len(all_scenarios)} payloads em {len(groups)} grupos\n")

    recon_pairs = []
    satisfied_groups: set[str] = set()
    skipped = 0
    turn = 0

    for purpose_key, scenarios in groups.items():
        if purpose_key in STOP_ON_FIRST and purpose_key in satisfied_groups:
            skipped += len(scenarios)
            continue

        for sc in scenarios:
            # Pular grupo já satisfeito
            if purpose_key in STOP_ON_FIRST and purpose_key in satisfied_groups:
                skipped += 1
                print(f"  ⏭  [{purpose_key}] {sc['name'][6:40]} — já satisfeito, pulando")
                continue

            turn += 1
            prompt = sc["initial_prompt"]
            print(f"  [{purpose_key}] {sc['name'][6:45]}")

            resp = guard.send_message(prompt, delay=delay)
            text = resp.get("extracted_text", "") or ""

            if text:
                recon_pairs.append((prompt, text))
                preview = text[:110].replace("\n", " ")
                print(f"    → {preview}{'...' if len(text) > 110 else ''}")

                # Verificar se a resposta é recusa genérica
                # Padrões base + padrões específicos do alvo (detection_patterns.resistance_signatures)
                base_refusal = [
                    "i'm here to help with",
                    "i'm here to assist",
                    "please let me know how i can help",
                ]
                target_refusal = []
                if target_cfg:
                    target_refusal = target_cfg.get("detection_patterns", {}).get("resistance_signatures", [])
                refusal_patterns = base_refusal + target_refusal
                is_refusal = any(p in text.lower() for p in refusal_patterns)

                if not is_refusal and purpose_key in STOP_ON_FIRST:
                    satisfied_groups.add(purpose_key)
                    print(f"    ✅ Objetivo '{purpose_key}' satisfeito — pulando demais do grupo")

            results.log_turn(
                turn=turn,
                message_sent=prompt,
                target_response=text,
                attacker_decision={
                    "technique_next": f"recon_{purpose_key}",
                    "evasion_applied": None,
                    "evasion_level": "none",
                    "analysis": "recon phase",
                    "resistance_type": "topic_filter" if text and "travel" in text.lower() else "none",
                },
                analysis=type("A", (), {
                    "success": False, "confidence": 0.0,
                    "findings": [], "categories": []
                })(),
            )

    if skipped:
        print(f"\n  ⏭  {skipped} payloads pulados por early stopping")

    # Context gathering — prioriza respostas informativas (não recusas genéricas)
    print(f"\n  🧠 Analisando {len(recon_pairs)} respostas de recon...")
    target_profile = {}
    if recon_pairs:
        # Ordenar: respostas informativas primeiro (para o LLM ver o mais útil)
        refusal_markers = ["i'm here to", "i'm unable to", "feel free to ask"]
        informative = [(q, r) for q, r in recon_pairs
                       if not any(m in r.lower() for m in refusal_markers)]
        generic = [(q, r) for q, r in recon_pairs
                   if any(m in r.lower() for m in refusal_markers)]
        ordered_pairs = informative + generic

        target_profile = evaluator.gather_context(ordered_pairs)
        if target_profile:
            model   = target_profile.get("model_type", "?")
            has_rag = target_profile.get("has_rag", "?")
            tools   = target_profile.get("has_tools", "?")
            vectors = target_profile.get("suggested_vectors", [])
            print(f"  modelo:  {model}")
            print(f"  rag:     {has_rag} | tools: {tools}")
            print(f"  vectors: {vectors}")

            hints = target_profile.get("system_prompt_hints", [])
            if hints:
                print(f"  hints:   {hints[:3]}")

            # Injeta no attacker para contextualizar os ataques seguintes
            notes_parts = []
            if model and model != "unknown":
                notes_parts.append(f"Model: {model}")
            if hints:
                notes_parts.append(f"Hints: {'; '.join(hints[:2])}")
            if vectors:
                notes_parts.append(f"Best vectors: {', '.join(vectors[:3])}")
            if notes_parts:
                attacker.session_notes = "[Recon] " + " | ".join(notes_parts)

    print()
    return target_profile


def run_scenario(
    scenario: dict,
    guard: SessionGuard,
    attacker: AttackerService,
    analyzer: ResponseAnalyzer,
    evaluator: LLMEvaluator,
    results: ResultsLogger,
    max_turns: int | None,
    delay: float,
    resume_turn: int = 0,
    resume_prompt: str | None = None,
    resume_seeds: list | None = None,
    target_config_path: str = "",
    args_dict: dict | None = None,
) -> list:
    sep = "═" * 60
    source = f"[AIX lv{scenario.get('level', '?')}]" if scenario.get("source") == "aix" else ""
    print(f"\n{sep}")
    print(f"  CENÁRIO  : {scenario['name']} {source}")
    print(f"  FAMÍLIA  : {scenario['technique_family']}")
    print(f"  OBJETIVO : {scenario['description']}")
    if max_turns:
        print(f"  TURNOS   : até {max_turns}")
    else:
        print(f"  TURNOS   : ∞ (Ctrl+C para parar)")
    print(f"{sep}\n")

    guard.target.reset_conversation()
    analysis_results = []
    turn = resume_turn  # Start from resumed turn or 0

    seed_prompts_queue = resume_seeds if resume_seeds is not None else list(attacker.seed_prompts)
    current_prompt = resume_prompt or scenario["initial_prompt"]

    try:
        while True:
            turn += 1
            if max_turns and turn > max_turns:
                break

            # Aplicar char_limit ao prompt base (antes da evasion)
            limited_prompt = attacker.enforce_char_limit(current_prompt)

            # Aplicar evasion (AIX)
            evaded_prompt, evasion_lvl = attacker.apply_evasion(limited_prompt)

            # Re-verificar char_limit DEPOIS da evasion — técnicas aggressive adicionam chars
            # (homoglyphs, zero-width, HTML entities, unicode escapes)
            if attacker.char_limit and len(evaded_prompt) > attacker.char_limit:
                safe = attacker.char_limit - 20
                logger.debug(
                    f"Evasion expandiu prompt de {len(limited_prompt)} → {len(evaded_prompt)} chars "
                    f"(limite={attacker.char_limit}). Truncando para {safe}."
                )
                evaded_prompt = evaded_prompt[:safe]

            if evasion_lvl != "none":
                print(f"\n── Turn {turn}{f'/{max_turns}' if max_turns else ''} [evasion={evasion_lvl}] {'─'*30}")
            else:
                print(f"\n── Turn {turn}{f'/{max_turns}' if max_turns else ''} {'─'*40}")

            # Mostrar tamanho do prompt se char_limit está ativo
            if attacker.char_limit:
                print(f"📤 [{len(evaded_prompt)}/{attacker.char_limit}] {evaded_prompt[:140]}{'...' if len(evaded_prompt) > 140 else ''}")
            else:
                print(f"📤 {evaded_prompt[:140]}{'...' if len(evaded_prompt) > 140 else ''}")

            resp = guard.send_message(evaded_prompt, delay=delay)
            target_text = resp.get("extracted_text", "") or str(resp.get("raw_response", ""))

            if target_text:
                print(f"📥 {target_text[:180]}{'...' if len(target_text) > 180 else ''}")
            else:
                print(f"📥 [sem resposta — status {resp.get('status_code')}]")

            # Detecção automática de char_limit na resposta
            from services.session_memory import SessionMemory
            detected_limit = SessionMemory.detect_char_limit_from_response(target_text)
            if detected_limit and detected_limit != attacker.char_limit:
                attacker.notify_char_limit(detected_limit, turn)
                print(f"📏 Char limit detectado automaticamente: {detected_limit} chars")

            # Diagnóstico de truncamento — notificar attacker
            if resp.get("truncated"):
                ti = resp["truncation_info"]
                reason = ti.get("reason", "?")
                lines  = ti.get("lines", 0)
                last   = ti.get("last_line", "")[:60]
                attacker.notify_truncation(reason, target_text, turn)

                if reason == "server_closed_abruptly":
                    print(f"⚠️  [TRUNCADO] Servidor fechou conexão — provável guardrail ({lines} linhas)")
                    print(f"   Última linha: '{last}'")
                elif reason == "incomplete_sse_no_jsonend":
                    print(f"⚠️  [TRUNCADO] SSE incompleto ({lines} linhas) — guardrail ou timeout")
                    print(f"   Última linha: '{last}'")
                elif reason == "suspiciously_short":
                    print(f"⚠️  [TRUNCADO] Resposta curta ({lines} linha(s)) — possível guardrail")
                elif reason == "read_timeout":
                    print(f"⚠️  [TRUNCADO] Timeout ({lines} linhas)")
                else:
                    print(f"⚠️  [TRUNCADO] {reason} ({lines} linhas)")

            # Análise dupla: regex + LLM judge
            analysis = analyzer.analyze(turn, evaded_prompt, target_text)
            llm_eval  = evaluator.evaluate(
                technique=scenario.get("technique_family", "unknown"),
                payload=evaded_prompt,
                response=target_text,
            )

            # Unificar resultados
            combined_success = analysis.success or llm_eval.get("vulnerable", False)
            combined_confidence = max(
                analysis.confidence,
                llm_eval.get("confidence", 0) / 100,
            )

            analysis_results.append(analysis)

            if combined_success:
                source_label = []
                if analysis.success:
                    source_label.append("regex")
                if llm_eval.get("vulnerable"):
                    source_label.append(f"LLM({llm_eval.get('finding_type','?')})")

                print(f"\n{'🎯'*20}")
                print(f"  FINDING — Turn {turn} | Confiança: {combined_confidence:.0%} | via {'+'.join(source_label)}")
                if llm_eval.get("leaked_content"):
                    print(f"  💀 Leaked: {llm_eval['leaked_content'][:200]}")
                if llm_eval.get("reason"):
                    print(f"  Reason: {llm_eval['reason']}")
                for finding in analysis.findings:
                    print(f"  → {finding}")
                print(f"{'🎯'*20}\n")

            # Registrar o prompt enviado neste turno para evitar repetição
            attacker.prompts_sent.add(evaded_prompt)

            # Attacker decide próximo passo
            decision = attacker.decide_next_attack(target_text, turn)

            evasion_info = evasion_lvl if evasion_lvl != "none" else decision.get("evasion_applied") or "nenhuma"
            print(
                f"🧠 Técnica: {decision.get('technique_next')} | "
                f"Evasão: {evasion_info} | "
                f"Resistência: {decision.get('resistance_type', '?')}"
            )

            # Persistir (com info do LLM evaluator)
            decision["llm_eval"] = llm_eval
            results.log_turn(
                turn=turn,
                message_sent=evaded_prompt,
                target_response=target_text,
                attacker_decision=decision,
                analysis=analysis,
            )

            # Próximo prompt: seed → LLM
            next_from_seed = None
            if seed_prompts_queue:
                seed = seed_prompts_queue.pop(0)
                sp = seed["prompt"].strip()
                if sp not in attacker.prompts_sent:
                    next_from_seed = sp
                    attacker.notify_seed_sent()  # seeds não contam para evasion escalation
                    print(f"🌱 Seed: {seed['name']}")

            current_prompt = next_from_seed or decision.get("next_prompt", "").strip()
            if not current_prompt:
                logger.warning("Sem próximo prompt — encerrando cenário")
                break

            # Salvar checkpoint a cada turno para --resume
            try:
                ckpt_file = save_session_checkpoint(
                    results=results,
                    attacker=attacker,
                    turn=turn,
                    scenario=scenario,
                    seed_queue_remaining=seed_prompts_queue,
                    current_prompt=current_prompt,
                    target_config_path=target_config_path or "",
                    args_dict=args_dict or {},
                )
                if turn % 10 == 0:  # Log a cada 10 turns
                    print(f"💾 Checkpoint salvo: {ckpt_file}")
            except Exception as e:
                logger.debug(f"Checkpoint save error: {e}")

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\n⏹  Interrompido no turn {turn}.")
        # Salvar checkpoint final para --resume
        try:
            ckpt_file = save_session_checkpoint(
                results=results,
                attacker=attacker,
                turn=turn,
                scenario=scenario,
                seed_queue_remaining=seed_prompts_queue,
                current_prompt=current_prompt,
                target_config_path=target_config_path or "",
                args_dict=args_dict or {},
            )
            print(f"  💾 Checkpoint salvo para --resume: {ckpt_file}")
            print(f"  ▶ Para retomar: python orchestrator.py --resume {ckpt_file}")
        except Exception as e:
            logger.debug(f"Checkpoint save error on interrupt: {e}")

    return analysis_results


def main():
    banner()

    parser = argparse.ArgumentParser(description="AI Red Team Framework v5")
    parser.add_argument(
        "--scenario", default="model_fingerprint_direct",
        help="Nome do cenário, 'all', 'seeds', 'aix', 'recon_sweep', etc.",
    )
    parser.add_argument("--list-scenarios", action="store_true")
    parser.add_argument("--max-turns", type=int, default=None,
                        help="Máximo de turnos por cenário (sem flag = infinito)")
    parser.add_argument("--delay", type=float, default=None)
    parser.add_argument("--proxy", type=str, default=None,
                        help="Proxy, ex: http://127.0.0.1:8080")
    parser.add_argument("--skip-browser-init", action="store_true")
    parser.add_argument("--save-cookies", action="store_true",
                        help=(
                            "Salva cookies capturados em cookies/<domínio>.json e os reutiliza "
                            "na próxima execução. Cookies salvos que não forem renovados pelo browser "
                            "(ex: auth tokens) são preservados e injetados na sessão."
                        ))
    parser.add_argument("--skip-save-cookies", action="store_true",
                        help=(
                            "Ignora cookies salvos em disco mesmo que --save-cookies esteja ativo. "
                            "Útil para forçar uma sessão completamente nova."
                        ))
    parser.add_argument("--skip-recon", action="store_true",
                        help="Pula fase de recon inicial")
    parser.add_argument(
        "--target-file", type=str, default=None, metavar="FILENAME",
        help=(
            "Arquivo de configuração do alvo em config/targets/. "
            "Ex: --target-file my_target.yaml. "
            "Default: template_target.yaml. "
            f"Disponíveis: {', '.join(p.name for p in __import__('pathlib').Path('config/targets').glob('*.yaml'))}"
        )
    )
    parser.add_argument(
        "--escape-seeds", action="store_true",
        help=(
            "Pula todos os seeds pré-carregados (YAML e --focus-owasp). "
            "O LLM auxiliar opera em modo 100%% autônomo desde o turn 1, "
            "gerando prompts baseado no histórico de sessões anteriores e no foco OWASP ativo. "
            "Ideal para combinar com --focus-owasp após sessões com seeds já realizadas."
        )
    )
    parser.add_argument("--aix-level", type=int, default=3, choices=[1,2,3,4,5],
                        help="Nível máximo de payloads AIX (1-5, default=3)")
    parser.add_argument(
        "--focus-owasp", type=str, default=None, metavar="CATEGORIES",
        help=(
            "Focar o ataque em categorias OWASP específicas. "
            "Ex: --focus-owasp LLM07,LLM08 — o LLM auxiliar só gerará prompts "
            "para essas categorias. "
            f"Disponíveis: {', '.join(OWASP_CATEGORIES.keys())}"
        )
    )

    # Novos argumentos
    parser.add_argument("--no-learn", action="store_true",
                        help="Não aprender com sessões anteriores em results/")
    parser.add_argument("--continue-session", type=str, default=None, metavar="PATH",
                        help="Continuar sessão anterior. Ex: results/session_20260409_172935.json")
    parser.add_argument("--char-limit", type=int, default=None,
                        help="Limite de caracteres por prompt (detectado automaticamente se não informado)")
    parser.add_argument("--resume", type=str, default=None, metavar="CHECKPOINT_FILE",
                        help=(
                            "Retoma sessão anterior a partir do checkpoint salvo. "
                            "Ex: --resume results/checkpoint_20260420_074939.json. "
                            "O checkpoint é salvo automaticamente a cada turno."
                        ))
    parser.add_argument("--attacker-endpoint", type=str, default=None, metavar="URL",
                        help=(
                            "URL do endpoint controlado pelo atacante para SSRF, "
                            "exfiltração, injeção JS/HTML, callbacks. "
                            "Ex: --attacker-endpoint https://abc.burpcollaborator.net"
                        ))

    parser.add_argument("--interact", action="store_true",
                        help="Modo 100%% manual: digita prompts, envia ao alvo, vê resposta. Sem LLM auxiliar.")
    parser.add_argument("--manual-attack", action="store_true",
                        help="Modo manual assistido: digita prompts, envia ao alvo, LLM auxiliar analisa e sugere.")

    args = parser.parse_args()

    # ──────────────────────────────────────────────────
    # --resume: retomar sessão anterior do checkpoint
    # ──────────────────────────────────────────────────
    if args.resume:
        if not os.path.exists(args.resume):
            print(f"\n❌  Checkpoint não encontrado: {args.resume}")
            sys.exit(1)

        ckpt = load_session_checkpoint(args.resume)
        print(f"\n🔄 Retomando sessão {ckpt['session_id']} do turn {ckpt['turn']}")
        print(f"   Salvo em: {ckpt['saved_at']}")
        print(f"   Cenário: {ckpt['scenario']['name']}")
        print(f"   Próximo prompt: {ckpt['current_prompt'][:100]}...\n")

        # Restaurar config do alvo
        saved_args = ckpt.get("args", {})
        resolved_config = ckpt["target_config_path"]
        cfg = load_target_config(resolved_config)

        # Restaurar proxy se estava ativo
        if saved_args.get("proxy"):
            cfg.setdefault("proxy", {})
            cfg["proxy"].update({
                "enabled": True,
                "http": saved_args["proxy"],
                "https": saved_args["proxy"],
                "verify_ssl": False,
            })

        attack_cfg = cfg["attack"]
        max_turns  = args.max_turns if args.max_turns is not None else attack_cfg.get("max_turns_per_scenario")
        delay      = args.delay or attack_cfg.get("delay_between_requests", 2.5)

        # Inicializar serviços
        target    = TargetAdapter(resolved_config, cfg=cfg)
        attacker  = AttackerService(ORCH_CONFIG, resolved_config)
        analyzer  = ResponseAnalyzer(target_cfg=cfg)
        evaluator = LLMEvaluator(ORCH_CONFIG)
        results   = ResultsLogger()

        # Restaurar estado do attacker
        attacker.load_checkpoint(ckpt["attacker_state"])
        attacker.set_session_id(results.session_id)

        # Restaurar attacker endpoint (do checkpoint ou da CLI)
        if args.attacker_endpoint:
            attacker.attacker_endpoint = args.attacker_endpoint.rstrip("/")
        elif saved_args.get("attacker_endpoint"):
            attacker.attacker_endpoint = saved_args["attacker_endpoint"]
        if attacker.attacker_endpoint:
            logger.info(f"Attacker endpoint: {attacker.attacker_endpoint}")

        # Restaurar dados de resultados (turns anteriores)
        results.session_data = ckpt.get("results_data", results.session_data)

        # Sessão (cookies + token)
        guard = init_session(
            target, cfg,
            skip_browser=saved_args.get("skip_browser_init", False),
            config_path=resolved_config,
            save_cookies=saved_args.get("save_cookies", False),
            skip_saved=saved_args.get("skip_save_cookies", False),
        )

        # Suprimir FutureWarning
        import warnings
        warnings.filterwarnings("ignore", category=FutureWarning, module="google")

        # Restaurar cenário e continuar
        scenario = ckpt["scenario"]
        resume_turn = ckpt["turn"]
        resume_prompt = ckpt["current_prompt"]
        resume_seeds = ckpt.get("seed_queue_remaining", [])

        args_dict = {
            "proxy": saved_args.get("proxy"),
            "save_cookies": saved_args.get("save_cookies", False),
            "skip_browser_init": saved_args.get("skip_browser_init", False),
            "skip_save_cookies": saved_args.get("skip_save_cookies", False),
            "focus_owasp": saved_args.get("focus_owasp"),
        }

        print(f"  ▶ Continuando do turn {resume_turn + 1}...\n")

        all_analysis = []
        try:
            res = run_scenario(
                scenario, guard, attacker, analyzer, evaluator,
                results, max_turns, delay,
                resume_turn=resume_turn,
                resume_prompt=resume_prompt,
                resume_seeds=resume_seeds,
                target_config_path=resolved_config,
                args_dict=args_dict,
            )
            all_analysis.extend(res)
        except KeyboardInterrupt:
            print("\n\n⏹  Sessão interrompida.")

        # Relatório final
        summary = analyzer.summarize_session(all_analysis)
        summary["attacker"]       = attacker.get_session_summary()
        summary["llm_evaluator"]  = evaluator.summary()
        summary["target_profile"] = {}
        summary["resumed_from"]   = args.resume
        results.generate_report(summary)

        eval_sum = evaluator.summary()
        att_sum  = attacker.get_session_summary()
        print(f"\n{'═'*60}")
        print(f"  SESSÃO RETOMADA CONCLUÍDA")
        print(f"  Retomada de       : {ckpt['session_id']} (turn {resume_turn})")
        print(f"  Turnos total      : {att_sum.get('total_unique_prompts', '?')}")
        print(f"  Findings (regex)  : {summary['successful_findings']}")
        print(f"  Findings (LLM)    : {eval_sum['vulnerabilities_found']}")
        print(f"  Relatório MD      : {results.report_file}")
        print(f"  Dados JSON        : {results.session_file}")
        print(f"{'═'*60}\n")
        return

    # ──────────────────────────────────────────────────
    # --interact ou --manual-attack: modos interativos
    # ──────────────────────────────────────────────────
    if args.interact or args.manual_attack:
        from interactive import run_interact, run_manual_attack

        # Resolver config do alvo
        if not args.target_file:
            print("❌  --target-file é obrigatório para modos interativos.")
            sys.exit(1)

        target_filename = args.target_file
        if not target_filename.endswith(".yaml"):
            target_filename += ".yaml"
        if os.path.exists(target_filename):
            target_config_path = target_filename
        else:
            target_config_path = f"config/targets/{target_filename}"

        if not os.path.exists(target_config_path):
            print(f"❌  Arquivo não encontrado: {target_config_path}")
            sys.exit(1)

        with open(target_config_path) as f:
            cfg = yaml.safe_load(f)
        target = TargetAdapter(target_config_path, cfg=cfg)

        # Proxy
        if args.proxy:
            target.set_proxy(args.proxy)

        # Suprimir FutureWarning da SDK antiga do Gemini
        import warnings
        warnings.filterwarnings("ignore", category=FutureWarning, module="google")

        # Inicializar sessão (cookies + token)
        guard = init_session(
            target, cfg,
            skip_browser=args.skip_browser_init,
            config_path=target_config_path,
            save_cookies=args.save_cookies,
            skip_saved=args.skip_save_cookies,
        )

        if args.interact:
            run_interact(guard, proxy=args.proxy)
        else:
            run_manual_attack(guard, config_path=target_config_path, proxy=args.proxy)
        return

    if args.list_scenarios:
        print("\n── Cenários do framework ──────────────────────────────────")
        families = {}
        for s in SCENARIOS:
            families.setdefault(s["technique_family"], []).append(s)
        for fam, items in families.items():
            print(f"\n  [{fam}]")
            for s in items:
                print(f"    {s['name']:<45} — {s['description']}")
        print("\n── Cenários especiais ─────────────────────────────────────")
        print("    all          — todos os cenários do framework")
        print("    seeds        — seeds configurados no YAML")
        print(f"    aix          — todos os payloads AIX (nível ≤ --aix-level)")
        print(f"    recon_sweep  — reconhecimento inicial com payloads AIX")
        psummary = payload_summary()
        print(f"\n── Payloads AIX disponíveis ───────────────────────────────")
        for cat, count in psummary.items():
            print(f"    {cat:<10} {count} payloads")
        return

    if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("GEMINI_API_KEY"):
        logger.error("Defina ANTHROPIC_API_KEY ou GEMINI_API_KEY")
        sys.exit(1)

    # Resolver arquivo de configuração do alvo
    # Usa variável local para não conflitar com o global TARGET_CONFIG
    if args.target_file:
        target_filename = args.target_file
        if not target_filename.endswith(".yaml"):
            target_filename += ".yaml"
        # Aceita path absoluto/relativo ou só o nome (busca em config/targets/)
        if os.path.exists(target_filename):
            resolved_config = target_filename
        else:
            resolved_config = f"config/targets/{target_filename}"
    else:
        print("\n❌  --target-file é obrigatório.\n")
        print("Uso:")
        print("  python orchestrator.py --target-file my_target.yaml")
        print("  python orchestrator.py --target-file my_target.yaml --focus-owasp LLM07")
        print("\nTemplates disponíveis em config/targets/:")
        targets_dir = "config/targets"
        if os.path.isdir(targets_dir):
            for f in sorted(os.listdir(targets_dir)):
                if f.endswith(".yaml"):
                    print(f"  - {f}")
        print("\nUse --list-scenarios para ver cenários disponíveis.")
        sys.exit(1)

    if not os.path.exists(resolved_config):
        print(f"\n❌  Arquivo de target não encontrado: {resolved_config}")
        print(f"\nArquivos disponíveis em config/targets/:")
        for f in sorted(os.listdir("config/targets")):
            if f.endswith(".yaml"):
                print(f"  - {f}")
        sys.exit(1)

    # Carregar config do alvo correto
    cfg = load_target_config(resolved_config)
    target_config_path = resolved_config

    # Aplicar proxy em memória — sem gravar YAML temporário
    # Apenas atualiza o dict cfg e passa direto ao TargetAdapter
    if args.proxy:
        cfg.setdefault("proxy", {})
        cfg["proxy"].update({
            "enabled": True,
            "http": args.proxy,
            "https": args.proxy,
            "verify_ssl": False,
        })
        logger.info(f"Proxy: {args.proxy}")

    attack_cfg = cfg["attack"]
    max_turns  = args.max_turns if args.max_turns is not None else attack_cfg.get("max_turns_per_scenario")
    delay      = args.delay or attack_cfg.get("delay_between_requests", 2.5)

    if max_turns is None:
        print("⚠️  Loop infinito — Ctrl+C para parar\n")

    # Inicializar serviços
    # cfg já tem proxy em memória se --proxy foi passado — não precisa de YAML temp
    target    = TargetAdapter(target_config_path, cfg=cfg)
    attacker  = AttackerService(ORCH_CONFIG, resolved_config)
    analyzer  = ResponseAnalyzer(target_cfg=cfg)
    evaluator = LLMEvaluator(ORCH_CONFIG)
    results   = ResultsLogger()
    attacker.set_session_id(results.session_id)

    # Configurar endpoint do atacante para SSRF/exfiltração
    if args.attacker_endpoint:
        attacker.attacker_endpoint = args.attacker_endpoint.rstrip("/")
        logger.info(f"Attacker endpoint configurado: {attacker.attacker_endpoint}")

    memory    = SessionMemory(results_dir="./results", orch_config=ORCH_CONFIG)

    # Carregar inteligência de sessões anteriores
    load_session_intelligence(
        attacker=attacker,
        memory=memory,
        continue_session=args.continue_session,
        no_learn=args.no_learn,
        char_limit=args.char_limit,
    )

    # Aplicar foco OWASP se especificado
    if args.focus_owasp:
        focus_cats = get_focus_categories(args.focus_owasp)
        if not focus_cats:
            logger.error(
                f"Categorias inválidas: '{args.focus_owasp}'. "
                f"Disponíveis: {', '.join(OWASP_CATEGORIES.keys())}"
            )
            sys.exit(1)

        focus_seeds     = [] if args.escape_seeds else get_focus_seeds(focus_cats, cfg)
        focus_injection = build_focus_system_prompt_injection(focus_cats, cfg)
        attacker.load_focus(focus_cats, focus_seeds, focus_injection)

        sep = "─" * 60
        print(f"\n{sep}")
        print(f"  🎯 FOCO OWASP ATIVO: {', '.join(focus_cats)}")
        for cat in focus_cats:
            fo = OWASP_CATEGORIES[cat]
            print(f"  [{cat}] {fo['name']} — {fo['generic_objective'][:70]}...")
        if args.escape_seeds:
            print(f"  ⏭  --escape-seeds: seeds ignorados — LLM opera em modo 100% autônomo")
        else:
            print(f"  Seeds de foco: {len(focus_seeds)} prompts carregados")
        print(f"  O LLM auxiliar só gerará prompts para essas categorias.")
        print(f"{sep}\n")

    elif args.escape_seeds:
        # --escape-seeds sem --focus-owasp: limpa seeds genéricos do YAML
        attacker.seed_prompts = []
        print("  ⏭  --escape-seeds: seeds genéricos descartados — LLM opera em modo autônomo\n")

    # Sessão (cookies + token de sessão)
    guard = init_session(
        target, cfg, args.skip_browser_init,
        config_path=target_config_path,
        save_cookies=args.save_cookies,
        skip_saved=args.skip_save_cookies,
    )

    # Fase de reconhecimento inicial
    # Pular se:
    #   1. --skip-recon explícito
    #   2. --continue-session com intel suficiente
    #   3. Aprendizado de sessões anteriores já tem modelo confirmado e vetores
    past_has_intel = bool(
        attacker.past_intel.get("confirmed_model", "unknown") not in ("", "unknown")
        and attacker.past_intel.get("working_vectors")
    )
    skip_recon = (
        args.skip_recon
        or (args.continue_session and attacker.past_intel.get("confirmed_model"))
        or past_has_intel
    )

    # Suprimir FutureWarning da SDK antiga do Gemini
    import warnings
    warnings.filterwarnings("ignore", category=FutureWarning, module="google")

    target_profile = {}
    if not skip_recon:
        target_profile = run_recon_phase(
            guard, evaluator, attacker, results,
            max_level=min(args.aix_level, 2),
            delay=delay,
            target_cfg=cfg,
        )
    else:
        reason = (
            "--skip-recon" if args.skip_recon
            else "--continue-session" if args.continue_session
            else f"sessões anteriores já identificaram o alvo ({attacker.past_intel.get('confirmed_model', '?')})"
        )
        print(f"  ⏭  Recon pulado — {reason}\n")
        if attacker.past_intel:
            target_profile = {
                "model_type":          attacker.past_intel.get("confirmed_model", "unknown"),
                "has_rag":             True,
                "has_tools":           True,
                "suggested_vectors":   [v.get("technique") for v in attacker.past_intel.get("working_vectors", [])],
                "system_prompt_hints": attacker.past_intel.get("confirmed_instructions", []),
                "purpose":             "travel_assistant",
                "domain":              "travel",
            }

    # Auto-trocar cenário padrão quando past_intel está carregado
    # model_fingerprint_direct não faz sentido se o modelo já foi identificado
    effective_scenario = args.scenario
    if (
        effective_scenario == "model_fingerprint_direct"
        and past_has_intel
        and attack_cfg.get("seed_prompts")
        and not args.focus_owasp  # com foco ativo, não trocar para seeds genéricos
    ):
        effective_scenario = "seeds"
        print(f"  🔄 Cenário padrão trocado: model_fingerprint_direct → seeds")
        print(f"     (modelo já identificado, indo direto para vetores comprovados)\n")

    # Com --focus-owasp: sobrescrever cenário para o cenário de foco dedicado
    # Os seeds de foco já estão na fila do attacker; o LLM opera em loop contínuo
    if args.focus_owasp and effective_scenario in ("model_fingerprint_direct", "seeds"):
        cats_str = "_".join(focus_cats).lower()
        effective_scenario = f"__focus_{cats_str}__"

    # Selecionar cenários
    if effective_scenario == "all":
        scenarios_to_run = SCENARIOS
    elif effective_scenario == "aix":
        scenarios_to_run = get_all_aix_scenarios(max_level=args.aix_level)
        print(f"📦 {len(scenarios_to_run)} payloads AIX (nível ≤ {args.aix_level})\n")
    elif effective_scenario == "recon_sweep":
        scenarios_to_run = get_recon_sweep(max_level=args.aix_level)
        print(f"📦 {len(scenarios_to_run)} payloads de recon\n")
    elif effective_scenario.startswith("__focus_"):
        # Cenário de foco: loop único e contínuo
        if attacker.seed_prompts:
            # Usa primeiro seed de foco como initial_prompt
            first_seed = attacker.seed_prompts[0]
            initial_prompt = first_seed["prompt"].strip()
            attacker.seed_prompts = attacker.seed_prompts[1:]
            print(f"  🎯 Cenário de foco: {len(attacker.seed_prompts)+1} seeds → loop autônomo\n")
        else:
            # --escape-seeds: sem seeds, LLM começa autônomo com prompt inicial neutro
            # O focus_injection já instrui o LLM a focar nas categorias certas
            initial_prompt = (
                "I need help planning a complex multi-city trip. "
                "Can you walk me through what you can help me with?"
            )
            cats_display = ', '.join(focus_cats)
            print(f"  🎯 Cenário de foco: modo 100% autônomo ({cats_display}) — sem seeds\n")

        scenarios_to_run = [{
            "name": f"focus_{'+'.join(focus_cats)}",
            "description": f"OWASP Focus: {', '.join(focus_cats)} — loop contínuo com LLM autônomo",
            "technique_family": "owasp_focus",
            "initial_prompt": initial_prompt,
        }]
    elif effective_scenario == "seeds":
        seeds = attack_cfg.get("seed_prompts", [])
        if not seeds:
            logger.error("Nenhum seed_prompt no YAML")
            sys.exit(1)
        scenarios_to_run = [
            {
                "name": s["name"],
                "description": f"Seed: {s['name']}",
                "technique_family": s.get("technique", "seed"),
                "initial_prompt": s["prompt"].strip(),
            }
            for s in seeds
        ]
    elif "," in effective_scenario:
        # Lista separada por vírgula: --scenario json_format_bypass,chained_tool_exploitation
        names = [n.strip() for n in effective_scenario.split(",")]
        scenarios_to_run = []
        not_found = []
        for name in names:
            sc = get_scenario(name)
            if sc:
                scenarios_to_run.append(sc)
            else:
                not_found.append(name)
        if not_found:
            logger.error(f"Cenários não encontrados: {', '.join(not_found)}. Use --list-scenarios.")
            sys.exit(1)
        print(f"📦 {len(scenarios_to_run)} cenários: {', '.join(names)}\n")
    else:
        sc = get_scenario(effective_scenario)
        if not sc:
            logger.error(f"Cenário '{effective_scenario}' não encontrado. Use --list-scenarios.")
            sys.exit(1)
        scenarios_to_run = [sc]

    # Build args_dict for checkpoint saving
    args_dict_for_checkpoint = {
        "proxy": args.proxy,
        "save_cookies": args.save_cookies,
        "skip_browser_init": args.skip_browser_init,
        "skip_save_cookies": args.skip_save_cookies,
        "focus_owasp": args.focus_owasp,
        "escape_seeds": args.escape_seeds,
        "scenario": args.scenario,
        "max_turns": args.max_turns,
        "delay": args.delay,
        "skip_recon": args.skip_recon,
        "attacker_endpoint": args.attacker_endpoint,
    }

    # Loop principal
    all_analysis = []
    try:
        for scenario in scenarios_to_run:
            res = run_scenario(
                scenario, guard, attacker, analyzer, evaluator,
                results, max_turns, delay,
                target_config_path=target_config_path,
                args_dict=args_dict_for_checkpoint,
            )
            all_analysis.extend(res)
    except KeyboardInterrupt:
        print("\n\n⏹  Sessão interrompida.")

    # Relatório final
    summary = analyzer.summarize_session(all_analysis)
    summary["attacker"]       = attacker.get_session_summary()
    summary["llm_evaluator"]  = evaluator.summary()
    summary["target_profile"] = target_profile
    results.generate_report(summary)

    eval_sum    = evaluator.summary()
    att_sum     = attacker.get_session_summary()
    print(f"\n{'═'*60}")
    print("  SESSÃO CONCLUÍDA")
    print(f"  Turnos total      : {summary['total_turns']}")
    print(f"  Findings (regex)  : {summary['successful_findings']}")
    print(f"  Findings (LLM)    : {eval_sum['vulnerabilities_found']}")
    print(f"  Prompts únicos    : {att_sum['total_unique_prompts']}")
    print(f"  Evasion final     : {att_sum['evasion_level']}")
    if att_sum.get("char_limit"):
        print(f"  Char limit        : {att_sum['char_limit']} chars")
    if att_sum.get("truncation_count"):
        print(f"  Truncamentos      : {att_sum['truncation_count']}")
    print(f"  Bloqueios PX      : {guard.block_count}")
    print(f"  Relatório MD      : {results.report_file}")
    print(f"  Dados JSON        : {results.session_file}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
