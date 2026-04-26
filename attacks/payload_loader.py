"""
attacks/payload_loader.py

Carrega os payloads do AIX (recon, extract, leak, rag, fuzz)
e os expõe como cenários compatíveis com o nosso orchestrator.

Os payloads são filtrados por nível (1=básico, 5=mais agressivo)
e podem ser usados como seeds ou como cenários completos.
"""
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

PAYLOADS_DIR = Path(__file__).parent / "payloads"


def _load(filename: str) -> list[dict]:
    path = PAYLOADS_DIR / filename
    try:
        d = json.loads(path.read_text())
        return d if isinstance(d, list) else d.get("payloads", [])
    except Exception as e:
        logger.error(f"Erro ao carregar {filename}: {e}")
        return []


def get_payloads(
    category: str,
    max_level: int = 3,
    limit: int = None,
    purpose_filter: str = None,
) -> list[dict]:
    """
    Retorna payloads de uma categoria filtrados por nível.

    category: recon | extract | leak | rag | fuzz
    max_level: 1-5 (1=apenas básico, 5=tudo)
    limit: máximo de payloads a retornar
    purpose_filter: filtrar por campo 'purpose' ou 'category'
    """
    filename_map = {
        "recon":   "recon.json",
        "extract": "extract.json",
        "leak":    "leak.json",
        "rag":     "rag.json",
        "fuzz":    "fuzz.json",
    }
    if category not in filename_map:
        logger.warning(f"Categoria desconhecida: {category}")
        return []

    items = _load(filename_map[category])

    # Filtrar por nível
    items = [i for i in items if i.get("level", 1) <= max_level]

    # Filtrar por purpose/category
    if purpose_filter:
        items = [
            i for i in items
            if purpose_filter in (i.get("purpose", "") + i.get("category", ""))
        ]

    if limit:
        items = items[:limit]

    return items


def payloads_as_scenarios(
    category: str,
    technique_family: str,
    max_level: int = 3,
    limit: int = None,
) -> list[dict]:
    """
    Converte payloads do AIX em formato de cenário do nosso orchestrator.
    """
    items = get_payloads(category, max_level=max_level, limit=limit)
    scenarios = []
    for item in items:
        payload_text = item.get("payload", "").strip()
        if not payload_text:
            continue
        scenarios.append({
            "name": f"{category}_{item.get('name', 'unknown')}",
            "description": item.get("purpose", item.get("category", category)),
            "technique_family": technique_family,
            "initial_prompt": payload_text,
            "source": "aix",
            "level": item.get("level", 1),
            "purpose": item.get("purpose", item.get("category", "other")),  # preservar para early stopping
        })
    return scenarios


# ------------------------------------------------------------------
# Cenários prontos para uso direto no orchestrator
# ------------------------------------------------------------------

def get_recon_sweep(max_level: int = 2) -> list[dict]:
    """
    Varredura de reconhecimento — ferramentas, capabilities, RAG, system prompt.
    Nível 1-2 para ser furtivo.
    """
    return payloads_as_scenarios("recon", "reconnaissance", max_level=max_level)


def get_extract_scenarios(max_level: int = 3) -> list[dict]:
    """Extração de system prompt via completions, tradução, roleplay, etc."""
    return payloads_as_scenarios("extract", "system_prompt_extraction", max_level=max_level)


def get_rag_scenarios(max_level: int = 3) -> list[dict]:
    """Ataques RAG: indirect injection, context poisoning, kb extraction."""
    return payloads_as_scenarios("rag", "rag_attack", max_level=max_level)


def get_leak_scenarios(max_level: int = 3) -> list[dict]:
    """Data leak: RAG context, credentials, internal docs."""
    return payloads_as_scenarios("leak", "data_leak", max_level=max_level)


def get_fuzz_scenarios(max_level: int = 2) -> list[dict]:
    """Fuzzing: encoding, unicode, boundary, format strings."""
    return payloads_as_scenarios("fuzz", "fuzzing", max_level=max_level)


def get_all_aix_scenarios(max_level: int = 3) -> list[dict]:
    """Todos os payloads do AIX como cenários, ordenados por nível."""
    all_sc = (
        get_recon_sweep(max_level) +
        get_extract_scenarios(max_level) +
        get_rag_scenarios(max_level) +
        get_leak_scenarios(max_level) +
        get_fuzz_scenarios(max_level)
    )
    # Ordenar: nível mais baixo primeiro
    return sorted(all_sc, key=lambda s: s.get("level", 1))


def summary() -> dict:
    """Resumo dos payloads disponíveis."""
    return {
        cat: len(get_payloads(cat, max_level=5))
        for cat in ("recon", "extract", "leak", "rag", "fuzz")
    }
