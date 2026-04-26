"""
services/cookie_manager.py

Abre o Chrome real via Playwright para que o humano resolva
desafios antibot (PerimeterX, Cloudflare, CAPTCHA).
Após resolução, captura os cookies automaticamente e injeta
na sessão do TargetAdapter.

Fluxo:
  1. Script detecta bloqueio (status 403, PX challenge, etc.)
  2. CookieManager.refresh() é chamado
  3. Abre janela Chrome com a URL alvo
  4. Aguarda sinal do humano (Enter no terminal) após resolver o desafio
  5. Captura todos os cookies relevantes do browser
  6. Injeta na sessão do TargetAdapter
  7. Retorna controle para o loop de ataque
"""
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

def _load_critical_cookies(config_path: str = None, cfg: dict = None) -> list:
    """
    Carrega a lista de cookies críticos do cfg dict ou do YAML do alvo.
    Fallback para lista genérica de antibot se não configurado.
    """
    # Preferir cfg dict em memória (suporta proxy aplicado)
    if cfg:
        cookies = cfg.get("browser", {}).get("critical_cookies", [])
        if cookies:
            return cookies
    if config_path:
        try:
            import yaml
            with open(config_path) as f:
                loaded = yaml.safe_load(f)
            cookies = loaded.get("browser", {}).get("critical_cookies", [])
            if cookies:
                return cookies
        except Exception:
            pass
    # Fallback genérico — cobre Cloudflare + PerimeterX + Forter
    return [
        "cf_clearance", "__cf_bm",
        "_px2", "_px3", "_pxde", "_pxvid", "pxcts",
        "forterToken",
    ]


# ─── Persistência de cookies ──────────────────────────────────────────────────

class CookiePersistence:
    """
    Salva e carrega cookies em arquivo JSON no diretório ./cookies/.
    Nome do arquivo: cookies/<domínio>.json
    Ex: cookies/www.example.com.json

    Lógica de merge:
      - Cookies do browser (frescos) sobrescrevem os salvos
      - Cookies salvos que NÃO vieram do browser são preservados
        (ex: tokens de autenticação que só aparecem após login e não são renovados sempre)
    """

    def __init__(self, domain: str, cookies_dir: str = "./cookies"):
        self._dir  = Path(cookies_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        # Normalizar domínio para nome de arquivo seguro
        safe = domain.replace("https://", "").replace("http://", "").rstrip("/")
        self._path = self._dir / f"{safe}.json"

    def load(self) -> dict:
        """Carrega cookies salvos do arquivo. Retorna {} se não existir."""
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            logger.info(
                f"Cookies salvos carregados ({len(data)}): "
                f"{list(data.keys())[:8]} de {self._path.name}"
            )
            return data
        except Exception as e:
            logger.warning(f"Erro ao carregar cookies salvos: {e}")
            return {}

    def save(self, cookies: dict) -> None:
        """Salva cookies no arquivo."""
        try:
            self._path.write_text(
                json.dumps(cookies, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info(f"Cookies salvos ({len(cookies)}) → {self._path}")
        except Exception as e:
            logger.warning(f"Erro ao salvar cookies: {e}")

    def merge(self, saved: dict, fresh: dict) -> dict:
        """
        Merge cookies: fresh sobrescreve saved para chaves em comum.
        Cookies em saved mas não em fresh são preservados (ex: auth tokens de longa duração).
        """
        merged = {**saved, **fresh}  # fresh wins para chaves duplicadas
        preserved = {k for k in saved if k not in fresh}
        if preserved:
            logger.info(f"Cookies preservados do arquivo salvo: {sorted(preserved)}")
        return merged

    @property
    def path(self) -> Path:
        return self._path


def _load_critical_cookies(config_path: str = None, cfg: dict = None) -> list:
    """
    Carrega a lista de cookies críticos do cfg dict ou do YAML do alvo.
    Fallback para lista genérica de antibot se não configurado.
    """
    # Preferir cfg dict em memória (suporta proxy aplicado)
    if cfg:
        cookies = cfg.get("browser", {}).get("critical_cookies", [])
        if cookies:
            return cookies
    if config_path:
        try:
            import yaml
            with open(config_path) as f:
                loaded = yaml.safe_load(f)
            cookies = loaded.get("browser", {}).get("critical_cookies", [])
            if cookies:
                return cookies
        except Exception:
            pass
    # Fallback genérico — cobre Cloudflare + PerimeterX + Forter
    return [
        "cf_clearance", "__cf_bm",
        "_px2", "_px3", "_pxde", "_pxvid", "pxcts",
        "forterToken",
    ]


class CookieManager:
    """
    Gerencia captura e renovação de cookies via browser real.
    Usa Playwright com Chromium em modo headed (visível ao usuário).

    Parâmetros:
        save_cookies: se True, salva cookies capturados e reutiliza na próxima execução
        skip_saved:   se True, ignora cookies salvos mesmo se save_cookies=True
    """

    def __init__(self, target_url: str, headless: bool = False,
                 config_path: str = None, cfg: dict = None,
                 save_cookies: bool = False, skip_saved: bool = False):
        self.target_url    = target_url
        self.headless      = headless
        self.save_cookies  = save_cookies
        self.skip_saved    = skip_saved
        self._critical_cookies = _load_critical_cookies(config_path=config_path, cfg=cfg)
        self._playwright   = None
        self._browser      = None
        self._context      = None
        self._page         = None

        # Persistência — ativa se --save-cookies e não --skip-save-cookies
        self._persistence: CookiePersistence | None = None
        if save_cookies and not skip_saved:
            from urllib.parse import urlparse
            domain = urlparse(target_url).netloc or target_url
            self._persistence = CookiePersistence(domain=domain)

        self._check_playwright()

    def _check_playwright(self):
        try:
            from playwright.sync_api import sync_playwright
            self._sync_playwright = sync_playwright
        except ImportError:
            logger.error(
                "Playwright não instalado. Execute:\n"
                "  pip install playwright\n"
                "  playwright install chromium"
            )
            sys.exit(1)

    # ------------------------------------------------------------------
    # Fluxo principal
    # ------------------------------------------------------------------

    def load_saved_cookies(self) -> dict:
        """
        Carrega cookies salvos do arquivo (se persistência ativa).
        Retorna {} se --skip-save-cookies ou arquivo não existir.
        """
        if self._persistence:
            saved = self._persistence.load()
            if saved:
                print(
                    f"  💾 Cookies salvos encontrados ({len(saved)}): "
                    f"{list(saved.keys())[:6]}"
                    f"{' ...' if len(saved) > 6 else ''}"
                )
            return saved
        return {}

    def refresh(self, reason: str = "Sessão expirada ou bloqueio detectado") -> dict:
        """
        Abre o browser, aguarda resolução manual do antibot,
        captura e retorna os cookies.

        Se --save-cookies:
          - Faz merge com cookies salvos (saved que não vieram do browser são preservados)
          - Salva o resultado merged

        Returns:
            dict: cookies capturados (+ preservados do arquivo se aplicável)
        """
        print("\n" + "="*60)
        print("⚠️  INTERVENÇÃO HUMANA NECESSÁRIA")
        print("="*60)
        print(f"Motivo: {reason}")
        print(f"URL: {self.target_url}")
        print("\nO Chrome será aberto. Por favor:")
        print("  1. Resolva qualquer desafio antibot/CAPTCHA")
        print("  2. Aguarde a página carregar completamente")
        print("  3. Envie UMA mensagem qualquer para o agente")
        print("  4. Volte aqui e pressione ENTER")
        print("="*60 + "\n")

        with self._sync_playwright() as p:
            import os as _os
            browser = p.chromium.launch(
                headless=False,
                env={**_os.environ, "GRPC_VERBOSITY": "NONE", "GRPC_TRACE": ""},
                args=[
                    "--no-sandbox",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-infobars",
                    "--log-level=3",
                    "--silent-debugger-extension-api",
                ],
            )

            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/146.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="America/New_York",
            )

            page = context.new_page()

            try:
                logger.info(f"Navegando para {self.target_url}...")
                page.goto(self.target_url, wait_until="domcontentloaded", timeout=30000)

                input("\n>>> Pressione ENTER quando tiver resolvido o desafio e a página estiver carregada: ")

                cookies = context.cookies()
                fresh = self._filter_cookies(cookies)

                logger.info(f"Cookies capturados: {list(fresh.keys())}")
                print(f"\n✅ {len(fresh)} cookies capturados: {list(fresh.keys())}")

                # Merge com cookies salvos se persistência ativa
                if self._persistence:
                    saved = self._persistence.load()
                    if saved:
                        merged = self._persistence.merge(saved, fresh)
                        preserved_count = len(merged) - len(fresh)
                        if preserved_count > 0:
                            preserved = [k for k in saved if k not in fresh]
                            print(f"  🔄 {preserved_count} cookie(s) preservado(s) do arquivo: {preserved}")
                        self._persistence.save(merged)
                        return merged
                    else:
                        # Primeiro uso — salvar direto
                        self._persistence.save(fresh)

                return fresh

            except Exception as e:
                logger.error(f"Erro ao capturar cookies: {e}")
                return {}
            finally:
                browser.close()

    def _filter_cookies(self, raw_cookies: list) -> dict:
        """Filtra apenas os cookies relevantes para a sessão."""
        result = {}
        for cookie in raw_cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            if name in self._critical_cookies and value:
                result[name] = value
        return result

    # ------------------------------------------------------------------
    # Detector de bloqueio
    # ------------------------------------------------------------------

    @staticmethod
    def is_blocked(response: dict) -> tuple[bool, str]:
        """
        Analisa uma resposta do TargetAdapter e determina se está bloqueado.
        
        Returns:
            (is_blocked: bool, reason: str)
        """
        status = response.get("status_code", 200)
        raw = str(response.get("raw_response", ""))
        error = str(response.get("error", ""))

        # Status codes de bloqueio
        if status == 403:
            return True, f"HTTP 403 Forbidden — possível bloqueio PX/Cloudflare"
        if status == 429:
            return True, f"HTTP 429 Too Many Requests — rate limit atingido"
        if status == 0:
            return True, f"Sem resposta — possível timeout ou bloqueio de rede"

        # Padrões PX no body
        px_patterns = [
            "px-captcha",
            "pxCaptcha",
            "PerimeterX",
            "_pxOnCaptchaSuccess",
            "human challenge",
            "Access to this page has been denied",
            "cf-challenge",  # Cloudflare
            "Checking if the site connection is secure",
        ]
        for pattern in px_patterns:
            if pattern.lower() in raw.lower():
                return True, f"Padrão de bloqueio detectado no body: '{pattern}'"

        # Erros de conexão
        if "Connection" in error or "Timeout" in error:
            return True, f"Erro de conexão: {error}"

        return False, ""


class SessionGuard:
    """
    Wrapper que envolve o TargetAdapter com proteção automática de sessão.
    Detecta bloqueios e aciona CookieManager.refresh() automaticamente.
    """

    def __init__(self, target_adapter, cookie_manager: CookieManager, max_retries: int = 3):
        self.target = target_adapter
        self.cm = cookie_manager
        self.max_retries = max_retries
        self.block_count = 0

    def send_message(self, message: str, **kwargs) -> dict:
        """
        Envia mensagem com proteção automática contra bloqueio.
        Se bloqueado, aciona refresh de cookies + reinit de sessão e tenta novamente.
        """
        for attempt in range(1, self.max_retries + 1):
            response = self.target.send_message(message, **kwargs)

            blocked, reason = CookieManager.is_blocked(response)

            if not blocked:
                return response

            self.block_count += 1
            logger.warning(f"Bloqueio detectado (tentativa {attempt}/{self.max_retries}): {reason}")

            if attempt < self.max_retries:
                # Renovar cookies via browser
                new_cookies = self.cm.refresh(reason=reason)
                if new_cookies:
                    self.target.update_session_cookies(new_cookies)
                    # Após renovar cookies, reinicializar token de sessão
                    logger.info("Reinicializando sessão (retrieve-prompts) após renovação de cookies...")
                    self.target.init_session()
                    logger.info("Sessão reinicializada, retentando request...")
                    time.sleep(2)
                else:
                    logger.error("Não foi possível capturar novos cookies")
                    break
            else:
                logger.error(f"Máximo de tentativas atingido após {self.max_retries} bloqueios")

        return response  # retorna último response mesmo se bloqueado
