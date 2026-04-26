"""
services/target_adapter.py  (v4 - config-driven)

Adapter genérico para agentes de IA via HTTP/2 + SSE.
Todo comportamento específico do alvo é lido do YAML — zero hardcode.

Seções do YAML usadas:
  target.base_url          → URL base
  target.endpoints.chat    → endpoint de chat
  session_token            → como obter/renovar o token de sessão
  request                  → encoding, campos dinâmicos, formato da mensagem
  payload                  → campos config e enabled_actions
  response                 → como parsear a resposta SSE
  session.cookies/headers  → cookies e headers base
  proxy                    → configuração de proxy
"""
import datetime
import gzip
import json
import logging
import time
import uuid
import warnings

import httpx
import yaml

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

logger = logging.getLogger(__name__)


class TargetAdapter:
    """
    Adapter genérico para agentes de IA.
    Lê toda a configuração do YAML do alvo — sem conhecimento
    específico de nenhum alvo em particular.
    """

    def __init__(self, config_path: str, cfg: dict = None):
        """
        config_path: path do YAML do alvo (para logging e referência)
        cfg: dict já carregado (opcional) — permite passar config modificada
             em memória (ex: proxy aplicado) sem gravar arquivo temporário
        """
        if cfg is not None:
            self.config = cfg
        else:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)

        self.target      = self.config["target"]
        self.session_cfg = self.config["session"]
        self.proxy_cfg   = self.config.get("proxy", {})
        self.payload_cfg = self.config.get("payload", {})
        self.response_cfg= self.config.get("response", {})
        self.request_cfg = self.config.get("request", {})
        self.token_cfg   = self.config.get("session_token", {})
        self.base_url    = self.target["base_url"]

        # Nome do token lido de session_token.name no YAML do alvo
        self._token_name: str = self.token_cfg.get("name", "session_token")
        self._session_token: str = ""
        self.cguid: str = ""
        self.turn_count: int = 0

        self._client: httpx.Client = None
        self._build_client()
        self.cguid = self._resolve_cguid()

    @property
    def session_token(self) -> str:
        return self._session_token

    @session_token.setter
    def session_token(self, value: str):
        self._session_token = value

    # ------------------------------------------------------------------
    # Setup do cliente httpx
    # ------------------------------------------------------------------

    def _build_client(self):
        if self._client:
            self._client.close()

        cookies = {
            k: v for k, v in self.session_cfg.get("cookies", {}).items() if v
        }

        # Headers base hardcoded mínimos — sobrescritos pelo YAML
        base_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
        }
        # YAML tem prioridade total
        base_headers.update(self.session_cfg.get("headers", {}))

        proxy_url = None
        verify = True
        if self.proxy_cfg.get("enabled"):
            proxy_url = self.proxy_cfg.get("https") or self.proxy_cfg.get("http")
            verify = False
            logger.info(f"Proxy ativo: {proxy_url}")

        self._client = httpx.Client(
            http2=True,
            verify=verify,
            proxy=proxy_url,
            headers=base_headers,
            cookies=cookies,
            timeout=httpx.Timeout(60.0, connect=15.0),
            follow_redirects=True,
        )

    # ------------------------------------------------------------------
    # Resolução do cguid a partir dos cookies
    # ------------------------------------------------------------------

    def _resolve_cguid(self) -> str:
        """
        Extrai o identificador de sessão (cguid ou equivalente) usando
        a ordem de fontes definida em session_token.cguid_sources no YAML.
        """
        cookies = self.session_cfg.get("cookies", {})
        sources = self.token_cfg.get("cguid_sources", [{"fallback": "uuid4"}])
        for src in sources:
            if "cookie" in src:
                val = cookies.get(src["cookie"], "")
                if not val:
                    continue
                if "prefix" in src and val.startswith(src["prefix"]):
                    return val[len(src["prefix"]):]
                if "split" in src and src["split"] in val:
                    return val.split(src["split"])[src.get("index", 0)]
                if val:
                    return val
            elif src.get("fallback") == "uuid4":
                return uuid.uuid4().hex
        return uuid.uuid4().hex

    def update_session_cookies(self, cookies: dict):
        """Atualiza cookies em runtime após renovação antibot via Playwright."""
        cfg_cookies = self.session_cfg.setdefault("cookies", {})
        cfg_cookies.update({k: v for k, v in cookies.items() if v})
        self.cguid = self._resolve_cguid()
        self._build_client()
        logger.info(f"Cookies atualizados e cliente recriado: {list(cookies.keys())}")

    # ------------------------------------------------------------------
    # Greeting (opcional)
    # ------------------------------------------------------------------

    def get_greeting(self) -> str:
        """
        Obtém a saudação inicial do agente via target.endpoints.greeting.
        Retorna string vazia se o endpoint não estiver configurado.
        """
        endpoint = self.target.get("endpoints", {}).get("greeting", "")
        if not endpoint:
            return ""
        url = f"{self.base_url}{endpoint}"
        import datetime
        now = datetime.datetime.now().strftime("%-m/%-d/%Y, %I:%M:%S %p")
        payload = {
            "isSessionActive": True,
            "dateToday": now,
            "cguid": self.cguid,
        }
        if self._session_token:
            payload[self.token_cfg.get("payload_field", "session_token")] = self._session_token
        try:
            resp = self._client.post(
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            if resp.is_success:
                data = resp.json()
                msg = data.get("message") or data.get("mainMessage", "")
                logger.info(f"Greeting: {msg[:100]}")
                return msg
        except Exception as e:
            logger.warning(f"Erro em get_greeting: {e}")
        return ""

    # ------------------------------------------------------------------
    # Inicialização do token de sessão
    # ------------------------------------------------------------------

    def init_session(self) -> bool:
        """
        Obtém o token de sessão via o endpoint configurado em
        session_token.init_endpoint.
        """
        endpoint = self.token_cfg.get("init_endpoint", "")
        if not endpoint:
            logger.warning("session_token.init_endpoint não configurado — pulando init")
            return True

        url = f"{self.base_url}{endpoint}"

        # Montar payload substituindo placeholders
        raw_payload = self.token_cfg.get("init_payload", {})
        payload = {}
        for k, v in raw_payload.items():
            if v == "{cguid}":
                payload[k] = self.cguid
            elif v == "{session_token}":
                payload[k] = self._session_token
            else:
                payload[k] = v

        try:
            resp = self._client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            field = self.token_cfg.get("response_field", "token")
            token = data.get(field, "")
            if token:
                self._session_token = token
                logger.info(f"{self._token_name} obtido: {token[:50]}...")
                return True
            logger.warning(f"init_session sem token no campo '{field}': {data}")
            return False
        except Exception as e:
            logger.error(f"Erro em init_session: {e}")
            return False

    # ------------------------------------------------------------------
    # Envio de mensagem
    # ------------------------------------------------------------------

    def send_message(self, message: str, extra_payload_fields: dict = None, delay: float = 0) -> dict:
        """
        Envia mensagem ao agente alvo.
        Monta o payload inteiramente a partir do YAML.
        """
        if delay:
            time.sleep(delay)

        if not self._session_token:
            logger.info(f"Sem {self._token_name} — inicializando sessão...")
            self.init_session()

        self.turn_count += 1
        now = datetime.datetime.now().strftime("%-m/%-d/%Y, %I:%M:%S %p")

        # Campos fixos do payload (payload.config_fields no YAML)
        payload = dict(self.payload_cfg.get("config_fields", {}))

        # Campos dinâmicos (request.dynamic_fields no YAML)
        dynamic = self.request_cfg.get("dynamic_fields", [])
        for field_def in dynamic:
            field_name = field_def["field"]
            raw_val    = field_def["value"]
            if raw_val == "{session_token}":
                payload[field_name] = self._session_token
            elif raw_val == "{cguid}":
                payload[field_name] = self.cguid
            elif raw_val == "{datetime_now}":
                payload[field_name] = now
            else:
                payload[field_name] = raw_val

        # enabled_actions (payload.enabled_actions no YAML)
        enabled_actions = self.payload_cfg.get("enabled_actions", {})
        if enabled_actions:
            payload["enabledActions"] = enabled_actions

        # Mensagem do usuário
        msg_field  = self.request_cfg.get("message_field",
                     self.payload_cfg.get("message_field", "messages"))
        msg_format = self.request_cfg.get("message_format", None)
        if msg_format:
            msg_obj = {k: (message if v == "{message}" else v)
                       for k, v in msg_format.items()}
            payload[msg_field] = [msg_obj]
        else:
            payload[msg_field] = message

        if extra_payload_fields:
            payload.update(extra_payload_fields)

        # Encoding do body
        encoding = self.request_cfg.get("body_encoding",
                   self.target.get("request_encoding", "json"))
        raw_body = json.dumps(payload).encode("utf-8")
        if encoding == "gzip":
            body = gzip.compress(raw_body)
        else:
            body = raw_body

        endpoint = self.target["endpoints"].get("chat", "/chat")
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Content-Type": self.request_cfg.get("content_type", "application/json"),
            "Accept":        self.request_cfg.get("accept", "application/json"),
            "Cache-Control": "no-cache",
        }
        if encoding == "gzip":
            headers["Content-Encoding"] = "gzip"

        logger.info(f"[Turn {self.turn_count}] Enviando: {message[:80]}...")

        try:
            with self._client.stream("POST", url, content=body, headers=headers) as resp:
                if resp.status_code == 403:
                    return self._blocked(resp.status_code, message, "403 — bloqueio PX/Cloudflare")
                if resp.status_code == 429:
                    return self._blocked(resp.status_code, message, "429 — rate limit")
                resp.raise_for_status()

                self._last_truncation = {}
                text, events = self._parse_sse(resp)
                truncation = getattr(self, "_last_truncation", {})

                # Renovar token se vier no header de resposta
                token_header = self.token_cfg.get("response_header", "")
                if token_header:
                    new_tok = resp.headers.get(token_header) or resp.headers.get(token_header.lower())
                    if new_tok and new_tok != self._session_token:
                        self._session_token = new_tok
                        logger.debug(f"{self._token_name} renovado via response header")

            if truncation:
                logger.warning(
                    f"[Turn {self.turn_count}] Resposta truncada "
                    f"({truncation.get('reason')}) — texto coletado: {len(text)} chars"
                )
            else:
                logger.info(f"[Turn {self.turn_count}] Resposta: {text[:120]}...")

            return {
                "success": True,
                "extracted_text": text,
                "raw_response": "\n".join(events),
                "status_code": resp.status_code,
                "turn": self.turn_count,
                "message_sent": message,
                "sse_events": events,
                "truncated": bool(truncation),
                "truncation_info": truncation or None,
            }

        except httpx.HTTPStatusError as e:
            sc = e.response.status_code
            logger.error(f"HTTP {sc}: {e.response.text[:200]}")
            return self._error(sc, message, str(e))
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
            return self._error(0, message, str(e))

    # ------------------------------------------------------------------
    # SSE parser (genérico — usa response.text_marker do YAML)
    # ------------------------------------------------------------------

    def _parse_sse(self, response: httpx.Response) -> tuple[str, list[str]]:
        text_marker    = self.response_cfg.get("text_marker", "jsonstart")
        text_end_marker= "jsonend"

        events: list[str] = []
        text_parts: list[str] = []
        in_json_section  = False
        saw_jsonstart    = False
        saw_jsonend      = False
        last_line        = ""
        line_count       = 0

        stream_ended_cleanly = False
        truncation_reason    = None
        stream_exception     = None

        try:
            for line in response.iter_lines():
                line_count += 1
                last_line = line
                if not line:
                    continue
                events.append(line)

                if line.strip() == text_marker:
                    in_json_section = True
                    saw_jsonstart   = True
                    continue
                if line.strip() == text_end_marker:
                    in_json_section = False
                    saw_jsonend     = True
                    continue

                if line.startswith(": ") or line.startswith("event:"):
                    continue

                if line.startswith("data:"):
                    data_str = line[5:].strip()
                    try:
                        obj = json.loads(data_str)
                        if "dynamicQuickActions" in obj:
                            continue
                        for key in ("message", "text", "content", "response"):
                            if isinstance(obj.get(key), str) and obj[key].strip():
                                text_parts.append(obj[key])
                                break
                    except json.JSONDecodeError:
                        if data_str:
                            text_parts.append(data_str)
                    continue

                if not in_json_section:
                    text_parts.append(line)

            stream_ended_cleanly = True

        except httpx.RemoteProtocolError as e:
            truncation_reason = "server_closed_abruptly"
            stream_exception  = str(e)
            logger.warning(f"[SSE] Servidor fechou conexão abruptamente: {e}")
        except httpx.ReadTimeout as e:
            truncation_reason = "read_timeout"
            stream_exception  = str(e)
            logger.warning(f"[SSE] Timeout lendo stream: {e}")
        except Exception as e:
            truncation_reason = f"exception:{type(e).__name__}"
            stream_exception  = str(e)
            logger.warning(f"[SSE] Exceção no stream ({type(e).__name__}): {e}")

        if stream_ended_cleanly:
            if saw_jsonstart and not saw_jsonend:
                truncation_reason = "incomplete_sse_no_jsonend"
                logger.warning(f"[SSE] Stream terminou sem jsonend ({line_count} linhas)")
            elif not saw_jsonstart and line_count < 3:
                truncation_reason = "suspiciously_short"
                logger.warning(f"[SSE] Resposta suspeita: {line_count} linha(s)")

        if truncation_reason:
            self._last_truncation = {
                "reason": truncation_reason,
                "lines": line_count,
                "saw_jsonstart": saw_jsonstart,
                "saw_jsonend": saw_jsonend,
                "last_line": last_line,
                "exception": stream_exception,
                "partial_events": events[-5:],
            }

        full_text = "\n".join(p for p in text_parts if p.strip()).strip()
        return full_text, events

    # ------------------------------------------------------------------
    # Ciclo de vida
    # ------------------------------------------------------------------

    def reset_conversation(self):
        """Reinicia conversa — novo token de sessão, mantém cookies."""
        self._session_token = ""
        self.turn_count = 0
        self.init_session()
        logger.info("Conversa reiniciada")

    def close(self):
        if self._client:
            self._client.close()

    # ------------------------------------------------------------------
    # Helpers de resposta
    # ------------------------------------------------------------------

    def _blocked(self, status: int, message: str, reason: str) -> dict:
        logger.warning(f"Bloqueado ({status}): {reason}")
        return {
            "success": False, "extracted_text": "", "raw_response": reason,
            "status_code": status, "turn": self.turn_count,
            "message_sent": message, "error": reason, "blocked": True,
        }

    def _error(self, status: int, message: str, error: str) -> dict:
        return {
            "success": False, "extracted_text": "", "raw_response": "",
            "status_code": status, "turn": self.turn_count,
            "message_sent": message, "error": error, "blocked": False,
        }
