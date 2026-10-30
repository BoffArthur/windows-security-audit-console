"""Windows Security Audit Console (WSAC).
Aplicativo local de auditoria e acompanhamento do Windows.
Requisito: pip install PySide6
"""
from __future__ import annotations

import ctypes
import datetime as dt
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QDateTime, QEvent, QObject, QThread, QTimer, Qt, Signal, Slot
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QKeySequence, QPainter, QPainterPath, QPalette, QPen, QPixmap, QShortcut
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDateTimeEdit, QFormLayout, QFrame, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
    QSplitter, QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTabWidget,
    QVBoxLayout, QWidget,
)
from ui.theme import STYLE, apply_palette
from ui.icons import icon as font_icon, status_icon

APP_NAME = "Windows Security Audit Console"
APP_VERSION = "1.8.0"
DB_NAME = "windows_security_audit.sqlite3"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
PAGE_SIZE = 100
IGNORED_POWERSHELL_EVENT_IDS = {40961, 40962, 53504}
CATEGORY_RETENTION_DAYS = {
    "PowerShell Operational": 30,
    "Windows PowerShell": 30,
    "Defender - eventos relevantes": 90,
    "Criação de processos - evento 4688": 30,
    "SENSE Operational": 30,
}
DEFAULT_EVENT_RETENTION_DAYS = 7

LOGS = [
    ("Microsoft-Windows-Windows Defender/Operational", "Defender"),
    ("Microsoft-Windows-SENSE/Operational", "SENSE"),
    ("Microsoft-Windows-PowerShell/Operational", "PowerShell"),
    ("Windows PowerShell", "Windows PowerShell"),
    ("Microsoft-Windows-TaskScheduler/Operational", "Agendador"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Sessões"),
    ("Security", "Criação de processos"),
]

SEVERITIES = ["INFORMATIVO", "MÉDIO", "ALTO", "CRÍTICO"]
ALERT_STATES = ["novo", "reconhecido", "resolvido", "ignorado"]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

DEFAULT_RULES = [
    ("defender_2050", 1, "INFORMATIVO", "IMPORTANTE", "Envios e coleta de arquivos", "Arquivo enviado para análise pelo Microsoft Defender"),
    ("defender_detection", 1, "ALTO", "NORMAL", "Detecção de ameaça", "O Microsoft Defender detectou uma ameaça"),
    ("defender_response", 1, "ALTO", "NORMAL", "Resposta a ameaça", "O Microsoft Defender executou uma ação"),
    ("defender_remediation_failure", 1, "CRÍTICO", "NORMAL", "Falha de correção", "Falha ao corrigir ou remover ameaça"),
    ("defender_protection_changed", 1, "CRÍTICO", "IMPORTANTE", "Proteção alterada", "Componente de proteção foi desativado ou alterado"),
    ("defender_config_changed", 1, "MÉDIO", "IMPORTANTE", "Configuração alterada", "Configuração do Microsoft Defender foi alterada"),
    ("remote_session", 1, "MÉDIO", "IMPORTANTE", "Sessão remota", "Sessão local ou remota registrada"),
    ("powershell_attention", 1, "ALTO", "IMPORTANTE", "PowerShell", "Comando PowerShell com indicador de atenção"),
    ("security_component_stopped", 1, "CRÍTICO", "IMPORTANTE", "Estado de segurança", "Componente de segurança inativo"),
]


DEFENDER_RELEVANT_IDS = {1006,1007,1008,1009,1015,1116,1117,1118,1119,1120,1121,1122,1125,1126,1127,1128,1129,1130,1150,1151,2001,2003,2010,2050,5001,5004,5007,5010,5012}
POWERSHELL_IDS = {400,403,4103,4104,4105,4106}

def classify_event_section(log_name: str, event_id: int) -> str:
    log = (log_name or "").lower()
    if "windows defender/operational" in log:
        return "Defender - eventos relevantes" if event_id in DEFENDER_RELEVANT_IDS else "Defender Operational"
    if "sense/operational" in log:
        return "SENSE Operational"
    if "powershell/operational" in log:
        return "PowerShell Operational"
    if log == "windows powershell":
        return "Windows PowerShell"
    if "taskscheduler/operational" in log:
        return "Task Scheduler"
    if "terminalservices-localsessionmanager/operational" in log:
        return "Sessões locais e remotas"
    if log == "security" and event_id == 4688:
        return "Criação de processos - evento 4688"
    if log == "security":
        return "Segurança do Windows"
    return "Outros eventos"


@dataclass
class EventRecord:
    computer: str
    log_name: str
    record_id: int
    event_id: int
    created_at: str
    provider: str
    level: str
    message: str
    category: str = "Outros eventos"


@dataclass
class AlertRecord:
    severity: str
    privacy: str
    category: str
    title: str
    details: str


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def display_datetime(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()
        return parsed.strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError):
        return value


class AuditDatabase:
    def __init__(self) -> None:
        self.path = Path(__file__).resolve().parent / DB_NAME
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.reset_incompatible_database()
        self.create_schema()

    def reset_incompatible_database(self) -> None:
        """Recria automaticamente apenas as tabelas incompatíveis desta versão."""
        def columns(table_name: str) -> set[str]:
            exists = self.connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
            ).fetchone()
            if not exists:
                return set()
            return {row["name"] for row in self.connection.execute(f"PRAGMA table_info({table_name})")}

        event_required = {
            "id", "computer", "log_name", "record_id", "event_id", "created_at",
            "last_seen_at", "provider", "level", "message", "message_hash",
            "category", "first_seen_at", "occurrence_count",
        }
        alert_required = {
            "id", "event_db_id", "created_at", "severity", "privacy_relevance",
            "category", "title", "details", "state", "updated_at",
        }
        events_columns = columns("events")
        alerts_columns = columns("alerts")
        status_columns = columns("status_current")
        incompatible = (
            (events_columns and not event_required.issubset(events_columns)) or
            (alerts_columns and not alert_required.issubset(alerts_columns)) or
            (events_columns and not status_columns)
        )
        if not incompatible:
            return

        self.connection.execute("PRAGMA foreign_keys=OFF")
        self.connection.executescript("""
            DROP TABLE IF EXISTS alerts;
            DROP TABLE IF EXISTS events;
            DROP TABLE IF EXISTS status_snapshots;
            DROP TABLE IF EXISTS status_current;
            DROP TABLE IF EXISTS status_changes;
            DROP TABLE IF EXISTS runs;
        """)
        self.connection.commit()
        self.connection.execute("PRAGMA foreign_keys=ON")

    def create_schema(self) -> None:
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS runs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL, finished_at TEXT,
            computer TEXT NOT NULL, username TEXT NOT NULL,
            mode TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'running', error TEXT
        );
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            computer TEXT NOT NULL, log_name TEXT NOT NULL, record_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
            provider TEXT, level TEXT, message BLOB NOT NULL, message_hash TEXT NOT NULL,
            category TEXT NOT NULL, first_seen_at TEXT NOT NULL, occurrence_count INTEGER NOT NULL DEFAULT 1,
            UNIQUE(computer,log_name,event_id,provider,category,message_hash)
        );
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_db_id INTEGER REFERENCES events(id) ON DELETE SET NULL,
            created_at TEXT NOT NULL, severity TEXT NOT NULL,
            privacy_relevance TEXT NOT NULL, category TEXT NOT NULL,
            title TEXT NOT NULL, details TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'novo', updated_at TEXT,
            UNIQUE(event_db_id,category,title)
        );
        CREATE TABLE IF NOT EXISTS alert_rules(
            rule_key TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1,
            severity TEXT NOT NULL, privacy_relevance TEXT NOT NULL,
            category TEXT NOT NULL, title TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS status_current(
            component TEXT PRIMARY KEY, observed_at TEXT NOT NULL,
            state TEXT NOT NULL, details TEXT
        );
        CREATE TABLE IF NOT EXISTS status_changes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at TEXT NOT NULL, component TEXT NOT NULL,
            previous_state TEXT, current_state TEXT NOT NULL, details TEXT
        );
        CREATE TABLE IF NOT EXISTS app_state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_filter ON events(event_id,level,provider,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_category_last_seen ON events(category,last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state,severity,created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_status_changes_component ON status_changes(component,observed_at DESC);
        """)
        self.connection.executemany(
            "INSERT OR IGNORE INTO alert_rules(rule_key,enabled,severity,privacy_relevance,category,title) VALUES(?,?,?,?,?,?)",
            DEFAULT_RULES,
        )
        self.connection.commit()

    def begin_run(self, mode: str) -> int:
        user = f"{os.getenv('USERDOMAIN','')}\\{os.getenv('USERNAME','')}".strip("\\")
        cur = self.connection.execute(
            "INSERT INTO runs(started_at,computer,username,mode) VALUES(?,?,?,?)",
            (now_iso(), platform.node(), user, mode),
        )
        self.connection.commit()
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, status: str, error: str | None = None) -> None:
        self.connection.execute(
            "UPDATE runs SET finished_at=?,status=?,error=? WHERE id=?",
            (now_iso(), status, error, run_id),
        )
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    @staticmethod
    def compress_message(message: str) -> bytes:
        return zlib.compress((message or "").encode("utf-8"), level=6)

    @staticmethod
    def decompress_message(payload) -> str:
        if payload is None: return ""
        if isinstance(payload, str): return payload
        try: return zlib.decompress(bytes(payload)).decode("utf-8", errors="replace")
        except Exception: return bytes(payload).decode("utf-8", errors="replace")

    def insert_event(self, event: EventRecord) -> tuple[int, bool]:
        normalized = (event.message or "").strip()
        message_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        existing = self.connection.execute(
            "SELECT id FROM events WHERE computer=? AND log_name=? AND event_id=? AND provider=? AND category=? AND message_hash=?",
            (event.computer,event.log_name,event.event_id,event.provider,event.category,message_hash),
        ).fetchone()
        if existing:
            self.connection.execute(
                "UPDATE events SET last_seen_at=?,record_id=?,occurrence_count=occurrence_count+1 WHERE id=?",
                (event.created_at,event.record_id,existing["id"]),
            )
            return int(existing["id"]), False
        cur = self.connection.execute(
            "INSERT INTO events(computer,log_name,record_id,event_id,created_at,last_seen_at,provider,level,message,message_hash,category,first_seen_at,occurrence_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (event.computer,event.log_name,event.record_id,event.event_id,event.created_at,event.created_at,
             event.provider,event.level,self.compress_message(normalized),message_hash,event.category,now_iso()),
        )
        return int(cur.lastrowid), True

    def insert_alert(self, event_db_id: int | None, alert: AlertRecord) -> bool:
        cur = self.connection.execute(
            "INSERT OR IGNORE INTO alerts(event_db_id,created_at,severity,privacy_relevance,category,title,details,state) VALUES(?,?,?,?,?,?,?,'novo')",
            (event_db_id, now_iso(), alert.severity, alert.privacy, alert.category, alert.title, alert.details),
        )
        return cur.rowcount > 0

    def add_snapshot(self, run_id: int, component: str, state: str, details: str = "") -> bool:
        previous = self.connection.execute("SELECT state,details FROM status_current WHERE component=?", (component,)).fetchone()
        changed = previous is None or previous["state"] != state or (previous["details"] or "") != (details or "")
        if not changed:
            return False
        observed = now_iso()
        self.connection.execute(
            "INSERT INTO status_current(component,observed_at,state,details) VALUES(?,?,?,?) ON CONFLICT(component) DO UPDATE SET observed_at=excluded.observed_at,state=excluded.state,details=excluded.details",
            (component,observed,state,details),
        )
        self.connection.execute(
            "INSERT INTO status_changes(observed_at,component,previous_state,current_state,details) VALUES(?,?,?,?,?)",
            (observed,component,previous["state"] if previous else None,state,details),
        )
        return True

    def rule(self, key: str):
        return self.connection.execute("SELECT * FROM alert_rules WHERE rule_key=?", (key,)).fetchone()

    def rules(self):
        return self.connection.execute("SELECT * FROM alert_rules ORDER BY category,title").fetchall()

    def update_rule(self, key: str, enabled: bool, severity: str) -> None:
        self.connection.execute(
            "UPDATE alert_rules SET enabled=?,severity=? WHERE rule_key=?",
            (1 if enabled else 0, severity, key),
        )
        self.connection.commit()

    @staticmethod
    def _filter_clause(filters: dict, alert: bool) -> tuple[str, list]:
        prefix = "a." if alert else ""
        conditions, values = [], []
        if filters.get("from"):
            conditions.append(f"{prefix}created_at>=?"); values.append(filters["from"])
        if filters.get("to"):
            conditions.append(f"{prefix}created_at<=?"); values.append(filters["to"])
        if filters.get("event_id"):
            conditions.append("e.event_id=?" if alert else "event_id=?"); values.append(filters["event_id"])
        if filters.get("level"):
            conditions.append("a.severity=?" if alert else "level LIKE ?")
            values.append(filters["level"] if alert else f"%{filters['level']}%")
        if filters.get("provider"):
            conditions.append("e.provider LIKE ?" if alert else "provider LIKE ?"); values.append(f"%{filters['provider']}%")
        if not alert and filters.get("category"):
            conditions.append("category=?"); values.append(filters["category"])
        if alert and filters.get("category"):
            conditions.append("a.category LIKE ?"); values.append(f"%{filters['category']}%")
        if alert and filters.get("state"):
            conditions.append("a.state=?"); values.append(filters["state"])
        if filters.get("text"):
            term = f"%{filters['text']}%"
            if alert:
                conditions.append("(a.title LIKE ? COLLATE NOCASE OR a.details LIKE ? COLLATE NOCASE OR a.category LIKE ? COLLATE NOCASE OR a.severity LIKE ? COLLATE NOCASE OR a.privacy_relevance LIKE ? COLLATE NOCASE OR a.state LIKE ? COLLATE NOCASE OR CAST(e.event_id AS TEXT) LIKE ? OR e.provider LIKE ? COLLATE NOCASE OR e.log_name LIKE ? COLLATE NOCASE)")
                values.extend([term] * 9)
            else:
                conditions.append("(message LIKE ? COLLATE NOCASE OR log_name LIKE ? COLLATE NOCASE OR provider LIKE ? COLLATE NOCASE OR level LIKE ? COLLATE NOCASE OR category LIKE ? COLLATE NOCASE OR CAST(event_id AS TEXT) LIKE ? OR CAST(record_id AS TEXT) LIKE ?)")
                values.extend([term] * 7)
        return (" WHERE " + " AND ".join(conditions) if conditions else ""), values

    def query_events(self, filters: dict, page: int, page_size: int):
        clause, params = self._filter_clause(filters, False)
        total = self.connection.execute("SELECT COUNT(*) FROM events" + clause, params).fetchone()[0]
        raw_rows = self.connection.execute(
            "SELECT * FROM events" + clause + " ORDER BY last_seen_at DESC LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        ).fetchall()
        rows = []
        for raw in raw_rows:
            row = dict(raw); row["message"] = self.decompress_message(row["message"]); rows.append(row)
        return rows, total

    def query_alerts(self, filters: dict, page: int, page_size: int):
        clause, params = self._filter_clause(filters, True)
        base = " FROM alerts a LEFT JOIN events e ON e.id=a.event_db_id" + clause
        total = self.connection.execute("SELECT COUNT(*)" + base, params).fetchone()[0]
        rows = self.connection.execute(
            "SELECT a.*,e.event_id source_event_id,e.provider,e.log_name,e.record_id" + base +
            " ORDER BY a.created_at DESC LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        ).fetchall()
        return rows, total

    def update_alert_state(self, alert_id: int, state: str) -> None:
        self.connection.execute("UPDATE alerts SET state=?,updated_at=? WHERE id=?", (state, now_iso(), alert_id)); self.connection.commit()

    def update_alerts_state(self, alert_ids: list[int], state: str) -> int:
        if not alert_ids: return 0
        marks = ",".join("?" for _ in alert_ids)
        cur = self.connection.execute(f"UPDATE alerts SET state=?,updated_at=? WHERE id IN ({marks})", [state, now_iso(), *alert_ids]); self.connection.commit(); return cur.rowcount

    def delete_alerts(self, alert_ids: list[int]) -> int:
        if not alert_ids: return 0
        marks = ",".join("?" for _ in alert_ids)
        cur = self.connection.execute(f"DELETE FROM alerts WHERE id IN ({marks})", alert_ids); self.connection.commit(); return cur.rowcount

    def alert_mood(self):
        rows = self.connection.execute("SELECT severity,COUNT(*) quantity FROM alerts WHERE state IN ('novo','reconhecido') GROUP BY severity").fetchall()
        counts = {row["severity"]: int(row["quantity"]) for row in rows}
        if counts.get("CRÍTICO", 0) > 0 or counts.get("ALTO", 0) > 0:
            return "ALERTA", "red"
        if counts.get("MÉDIO", 0) > 0:
            return "ATENÇÃO", "yellow"
        if counts.get("INFORMATIVO", 0) > 0:
            return "INFORMATIVO", "blue"
        return "SEM ALERTAS", "green"

    def current_status(self):
        return self.connection.execute("SELECT component,observed_at,state,details FROM status_current ORDER BY component").fetchall()

    def history(self, limit: int = 500):
        return self.connection.execute("""
            SELECT observed_at,component,COALESCE(previous_state,'(inicial)') previous_state,current_state,details
            FROM status_changes ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

    def get_setting(self, key: str, default: str) -> str:
        row = self.connection.execute("SELECT value FROM app_state WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: object) -> None:
        self.connection.execute(
            "INSERT INTO app_state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        self.connection.commit()

    def cleanup(self, retention_days: int, max_size_mb: int) -> None:
        now = dt.datetime.now().astimezone()
        categories = self.connection.execute("SELECT DISTINCT category FROM events").fetchall()
        for row in categories:
            category = row["category"]
            days = CATEGORY_RETENTION_DAYS.get(category, DEFAULT_EVENT_RETENTION_DAYS)
            cutoff = (now - dt.timedelta(days=days)).isoformat(timespec="seconds")
            self.connection.execute("DELETE FROM events WHERE category=? AND last_seen_at<?", (category,cutoff))
        alert_cutoff = (now - dt.timedelta(days=retention_days)).isoformat(timespec="seconds")
        self.connection.execute("DELETE FROM alerts WHERE created_at<?", (alert_cutoff,))
        self.connection.execute("DELETE FROM status_changes WHERE observed_at<?", (alert_cutoff,))
        self.connection.execute("DELETE FROM runs WHERE started_at<?", (alert_cutoff,))
        self.connection.commit(); self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        freelist = self.connection.execute("PRAGMA freelist_count").fetchone()[0]
        pages = max(1,self.connection.execute("PRAGMA page_count").fetchone()[0])
        if freelist / pages >= 0.20 or (self.path.exists() and self.path.stat().st_size > max_size_mb*1024*1024):
            self.connection.execute("VACUUM")

    def close(self) -> None:
        self.connection.close()


def ps_json(script: str, timeout: int = 60):
    prefix = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $OutputEncoding=[Text.UTF8Encoding]::new($false); "
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + script],
        capture_output=True, text=False, timeout=timeout, shell=False, creationflags=CREATE_NO_WINDOW,
    )
    raw = completed.stdout.decode("utf-8-sig", errors="replace").strip()
    err = completed.stderr.decode("utf-8-sig", errors="replace").strip()
    if completed.returncode and not raw:
        raise RuntimeError(err or f"PowerShell retornou {completed.returncode}")
    return json.loads(raw) if raw else []


def classify_event(event: EventRecord, db: AuditDatabase) -> list[AlertRecord]:
    keys: list[str] = []
    eid, msg = event.event_id, event.message.lower()
    if "defender" in event.provider.lower():
        if eid == 2050: keys.append("defender_2050")
        elif eid in {1006, 1116}: keys.append("defender_detection")
        elif eid in {1007, 1117}: keys.append("defender_response")
        elif eid in {1118, 1119, 1120}: keys.append("defender_remediation_failure")
        elif eid in {5001, 5010, 5012}: keys.append("defender_protection_changed")
        elif eid in {5004, 5007}: keys.append("defender_config_changed")
    if event.log_name.endswith("TerminalServices-LocalSessionManager/Operational") and eid in {21, 22, 25}:
        keys.append("remote_session")
    if event.log_name.endswith("PowerShell/Operational") and eid == 4104 and any(
        value in msg for value in ("downloadstring", "invoke-expression", "encodedcommand", "frombase64string")
    ):
        keys.append("powershell_attention")
    alerts = []
    for key in keys:
        rule = db.rule(key)
        if rule and rule["enabled"]:
            alerts.append(AlertRecord(rule["severity"], rule["privacy_relevance"], rule["category"], rule["title"], event.message))
    return alerts


class Collector(QObject):
    completed = Signal(object, object, object, object)
    failed = Signal(str)
    progress = Signal(str)

    def __init__(self, minutes: int) -> None:
        super().__init__()
        self.minutes = max(1, int(minutes))

    @staticmethod
    def normalise_rows(value):
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [value]
        return []

    @Slot()
    def run(self) -> None:
        statuses, events, errors = [], [], []
        computer = platform.node()
        try:
            self.progress.emit("COLETANDO STATUS DOS SERVIÇOS")
            services_script = r"""
$ErrorActionPreference = 'Stop'
$result = @(
    foreach ($name in @('Sense','WinDefend','WdNisSvc')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            [pscustomobject]@{Component=[string]$service.Name; State=[string]$service.Status; Details=[string]$service.DisplayName}
        } else {
            [pscustomobject]@{Component=[string]$name; State='Não encontrado'; Details='Serviço não localizado'}
        }
    }
)
$result | ConvertTo-Json -Depth 4 -Compress
"""
            try:
                statuses.extend(self.normalise_rows(ps_json(services_script, 45)))
            except Exception as exc:
                errors.append(f"Serviços: {exc}")

            self.progress.emit("COLETANDO STATUS DO DEFENDER")
            defender_script = r"""
$ErrorActionPreference = 'Stop'
$status = Get-MpComputerStatus
[pscustomobject]@{
    AntivirusEnabled=[bool]$status.AntivirusEnabled
    RealTimeProtectionEnabled=[bool]$status.RealTimeProtectionEnabled
    BehaviorMonitorEnabled=[bool]$status.BehaviorMonitorEnabled
    IoavProtectionEnabled=[bool]$status.IoavProtectionEnabled
    NISEnabled=[bool]$status.NISEnabled
    AntivirusSignatureLastUpdated=if($null -ne $status.AntivirusSignatureLastUpdated){$status.AntivirusSignatureLastUpdated.ToString('o')}else{''}
} | ConvertTo-Json -Depth 4 -Compress
"""
            try:
                mp_rows = self.normalise_rows(ps_json(defender_script, 45))
                if mp_rows:
                    mp = mp_rows[0]
                    for key in ("AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled", "NISEnabled"):
                        statuses.append({"Component": key, "State": "Ativo" if bool(mp.get(key)) else "Inativo", "Details": "Microsoft Defender"})
                    statuses.append({"Component": "Assinaturas do Defender", "State": "Disponível", "Details": str(mp.get("AntivirusSignatureLastUpdated") or "")})
            except Exception as exc:
                errors.append(f"Defender: {exc}")

            self.progress.emit("COLETANDO EVENTOS")
            for log_name, label in LOGS:
                safe_log = log_name.replace("'", "''")
                id_filter = "; Id=4688" if log_name == "Security" else ""
                event_script = f"""
$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddMinutes(-{self.minutes})
$items = @(
    Get-WinEvent -FilterHashtable @{{LogName='{safe_log}'; StartTime=$start{id_filter}}} -MaxEvents 1000 -ErrorAction Stop |
    ForEach-Object {{
        [pscustomobject]@{{
            RecordId=[long]$_.RecordId
            Id=[int]$_.Id
            TimeCreated=if($null -ne $_.TimeCreated){{$_.TimeCreated.ToUniversalTime().ToString('o')}}else{{''}}
            ProviderName=[string]$_.ProviderName
            LevelDisplayName=[string]$_.LevelDisplayName
            Message=[string]$_.Message
            LogName=[string]$_.LogName
        }}
    }}
)
$items | ConvertTo-Json -Depth 5 -Compress
"""
                try:
                    for row in self.normalise_rows(ps_json(event_script, 90)):
                        record_id = int(row.get("RecordId") or 0)
                        if record_id <= 0:
                            continue
                        event_id = int(row.get("Id") or 0)
                        if "powershell/operational" in log_name.lower() and event_id in IGNORED_POWERSHELL_EVENT_IDS:
                            continue
                        events.append(EventRecord(
                            computer=computer,
                            log_name=str(row.get("LogName") or log_name),
                            record_id=record_id,
                            event_id=event_id,
                            created_at=str(row.get("TimeCreated") or now_iso()),
                            provider=str(row.get("ProviderName") or label),
                            level=str(row.get("LevelDisplayName") or "Informações"),
                            message=str(row.get("Message") or ""),
                            category=classify_event_section(str(row.get("LogName") or log_name), event_id),
                        ))
                except Exception as exc:
                    errors.append(f"{label}: {exc}")

            self.completed.emit(statuses, events, errors, {
                "admin": bool(ctypes.windll.shell32.IsUserAnAdmin()) if os.name == "nt" else False,
                "status_count": len(statuses), "event_count": len(events),
            })
        except Exception as exc:
            self.failed.emit(f"Falha inesperada no coletor: {exc}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.db = AuditDatabase()
        self.thread = self.worker = self.run_id = None
        self.timer = QTimer(self); self.timer.timeout.connect(self.start_collection)
        self.countdown_timer = QTimer(self); self.countdown_timer.timeout.connect(self.update_countdown)
        self.next_collection_at: dt.datetime | None = None
        self.tray: QSystemTrayIcon | None = None
        self._tray_notice_shown = False
        self.alert_page = self.event_page = 1
        self._alerts, self._events = [], []
        self._home_alerts = []
        self.setWindowTitle(APP_NAME)
        self.resize(1440, 860); self.setMinimumSize(1080, 680)
        self.build_ui(); self.setup_tray(); self.refresh_all(); self.set_signal(*self.db.alert_mood()); self.log_terminal(f"{APP_NAME} {APP_VERSION} iniciado.", "SISTEMA")
        if self.start_monitor_check.isChecked(): QTimer.singleShot(500, self.toggle_monitor)

    def build_ui(self) -> None:
        root = QVBoxLayout(); root.setContentsMargins(10, 10, 10, 8); root.setSpacing(8)
        central = QWidget(); central.setLayout(root); self.setCentralWidget(central)
        toolbar = QFrame(objectName="toolbar"); row = QHBoxLayout(toolbar); row.setContentsMargins(8, 6, 8, 6)
        self.run_btn = QPushButton("[ F5 ] COLETAR HISTÓRICO", objectName="primary"); self.run_btn.setIcon(font_icon("collect")); self.run_btn.clicked.connect(self.start_collection); row.addWidget(self.run_btn)
        self.monitor_btn = QPushButton("[ F6 ] INICIAR MONITORAMENTO"); self.monitor_btn.clicked.connect(self.toggle_monitor); row.addWidget(self.monitor_btn)
        row.addStretch()
        signal_box = QFrame(objectName="signalBox"); signal_row = QHBoxLayout(signal_box); signal_row.setContentsMargins(5, 2, 5, 2)
        self.signal_dot = QLabel(); self.signal_text = QLabel(objectName="signal"); signal_row.addWidget(self.signal_dot); signal_row.addWidget(self.signal_text); row.addWidget(signal_box)
        root.addWidget(toolbar)
        self.tabs = QTabWidget(); root.addWidget(self.tabs, 1)
        self.home_page = self.make_home_tab(); self.tabs.addTab(self.home_page, "INÍCIO  [Ctrl+1]"); self.tabs.setTabIcon(0, font_icon("home"))
        self.alert_table, self.alert_view, alerts_tab = self.make_alerts_tab(); self.tabs.addTab(alerts_tab, "ALERTAS IMPORTANTES  [Ctrl+2]"); self.tabs.setTabIcon(1, font_icon("alerts"))
        self.event_table, self.event_view, events_tab = self.make_events_tab(); self.tabs.addTab(events_tab, "EVENTOS COLETADOS  [Ctrl+3]"); self.tabs.setTabIcon(2, font_icon("events"))
        self.status_table = self.make_table(["SINAL", "COMPONENTE", "ESTADO", "ÚLTIMA LEITURA", "DETALHES"], [70, 250, 120, 170, 500]); self.tabs.addTab(self.status_table, "STATUS DO SISTEMA  [Ctrl+4]"); self.tabs.setTabIcon(3, font_icon("status"))
        self.history_table = self.make_table(["DATA/HORA", "COMPONENTE", "ESTADO ANTERIOR", "ESTADO ATUAL", "DETALHES"], [170, 245, 150, 150, 500])
        history_tab = QWidget(); history_layout = QHBoxLayout(history_tab); history_layout.setContentsMargins(0, 0, 0, 0)
        history_split = QSplitter(Qt.Horizontal); history_split.addWidget(self.history_table)
        self.software_terminal = QPlainTextEdit(); self.software_terminal.setReadOnly(True); self.software_terminal.setMaximumBlockCount(1500); self.software_terminal.setLineWrapMode(QPlainTextEdit.WidgetWidth); self.software_terminal.setMinimumWidth(290)
        history_split.addWidget(self.software_terminal); history_split.setSizes([1030, 370]); history_layout.addWidget(history_split)
        self.tabs.addTab(history_tab, "HISTÓRICO  [Ctrl+5]"); self.tabs.setTabIcon(4, font_icon("history"))
        self.tabs.addTab(self.make_settings_tab(), "SOBRE / CONFIGURAÇÕES  [Ctrl+6]"); self.tabs.setTabIcon(5, font_icon("settings"))
        footer = QFrame(objectName="footer"); footer_row = QHBoxLayout(footer); footer_row.setContentsMargins(8, 4, 8, 4)
        self.footer = QLabel(f"PRONTO | BANCO: {self.db.path.name}", objectName="footerText"); footer_row.addWidget(self.footer); footer_row.addStretch()
        self.countdown_bar = QProgressBar(); self.countdown_bar.setRange(0, 1000); self.countdown_bar.setFixedWidth(120); self.countdown_bar.setToolTip("Tempo restante para a próxima coleta"); footer_row.addWidget(self.countdown_bar)
        self.countdown_label = QLabel("--:--", objectName="footerText"); footer_row.addWidget(self.countdown_label)
        footer_row.addWidget(QLabel("Desenvolvido por Arthur Boff", objectName="footerAuthor"), 0, Qt.AlignRight | Qt.AlignVCenter)
        root.addWidget(footer)
        self.event_sections.currentItemChanged.connect(lambda current, _previous: self.section_changed("events", current))
        self.alert_sections.currentItemChanged.connect(lambda current, _previous: self.section_changed("alerts", current))
        self.install_tab_shortcuts()

    def make_home_tab(self):
        page = QWidget(); layout = QVBoxLayout(page); layout.setContentsMargins(8, 8, 8, 8); layout.setSpacing(10)
        self.home_status_grid = QGridLayout(); self.home_status_grid.setSpacing(8)
        status_box = QFrame(objectName="toolbar"); status_layout = QVBoxLayout(status_box)
        status_layout.addWidget(QLabel("STATUS DE SEGURANÇA")); status_layout.addLayout(self.home_status_grid)
        layout.addWidget(status_box)

        alerts_box = QFrame(objectName="toolbar"); alerts_layout = QVBoxLayout(alerts_box)
        alerts_layout.addWidget(QLabel("ALERTAS ATIVOS"))
        alert_split = QSplitter(Qt.Horizontal)
        self.home_alert_list = QListWidget(); self.home_alert_list.setMinimumWidth(300)
        self.home_alert_detail = QPlainTextEdit(); self.home_alert_detail.setReadOnly(True)
        alert_split.addWidget(self.home_alert_list); alert_split.addWidget(self.home_alert_detail); alert_split.setSizes([420, 900])
        alerts_layout.addWidget(alert_split, 1)
        action_row = QHBoxLayout(); action_row.addStretch()
        self.home_mark_read = QPushButton("MARCAR ALERTA COMO LIDO")
        self.home_mark_read.setIcon(font_icon("status"))
        self.home_mark_read.clicked.connect(self.mark_home_alert_read)
        action_row.addWidget(self.home_mark_read); alerts_layout.addLayout(action_row)
        layout.addWidget(alerts_box, 1)
        self.home_alert_list.currentRowChanged.connect(self.show_home_alert)
        return page

    def show_home_alert(self, index: int):
        if not 0 <= index < len(self._home_alerts):
            self.home_alert_detail.clear(); self.home_mark_read.setEnabled(False); return
        record = self._home_alerts[index]
        self.home_alert_detail.setPlainText(
            f"{record['title']}\n\n"
            f"Severidade: {record['severity']}\n"
            f"Categoria: {record['category']}\n"
            f"Quando: {display_datetime(record['created_at'])}\n"
            f"Estado: {record['state']}\n\n"
            f"O que aconteceu:\n{record['details']}"
        )
        self.home_mark_read.setEnabled(record["state"] in {"novo", "reconhecido"})

    def mark_home_alert_read(self):
        index = self.home_alert_list.currentRow()
        if not 0 <= index < len(self._home_alerts): return
        self.db.update_alert_state(int(self._home_alerts[index]["id"]), "resolvido")
        self.refresh_all(); self.set_signal(*self.db.alert_mood())

    def refresh_home(self):
        statuses = self.db.current_status()
        while self.home_status_grid.count():
            item = self.home_status_grid.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        for index, record in enumerate(statuses):
            component = str(record["component"])
            state = str(record["state"] or "Indisponível")
            low = state.casefold()
            if low in {"inativo", "stopped", "parado", "disabled", "desativado", "false"}:
                color = "#FB7185"
            elif low in {"não encontrado", "indisponível", "unknown", "ausente"}:
                color = "#FBBF24"
            elif low == "disponível":
                color = "#22D3EE"
            else:
                color = "#60A5FA"
            card = QFrame(objectName="statusCard")
            card.setStyleSheet(f"QFrame#statusCard {{ background:#131E1C; border:1px solid {color}; border-left:5px solid {color}; border-radius:6px; }}")
            card_layout = QVBoxLayout(card); card_layout.setContentsMargins(12, 10, 12, 10)
            heading = QHBoxLayout()
            glyph = QLabel(); glyph.setPixmap(font_icon(status_icon(component), color, 19).pixmap(24, 24))
            title = QLabel(component); title.setStyleSheet(f"font-weight:700; color:{color};")
            heading.addWidget(glyph); heading.addWidget(title, 1); card_layout.addLayout(heading)
            state_label = QLabel(state.upper()); state_label.setStyleSheet(f"font-size:12pt; font-weight:700; color:{color};")
            detail = QLabel(record["details"] or display_datetime(record["observed_at"])); detail.setWordWrap(True)
            card_layout.addWidget(state_label); card_layout.addWidget(detail)
            self.home_status_grid.addWidget(card, index // 4, index % 4)

        fresh, _ = self.db.query_alerts({"state": "novo"}, 1, 100)
        acknowledged, _ = self.db.query_alerts({"state": "reconhecido"}, 1, 100)
        self._home_alerts = sorted([*fresh, *acknowledged], key=lambda row: row["created_at"], reverse=True)[:12]
        selected_id = None
        current = self.home_alert_list.currentRow()
        if 0 <= current < len(self._home_alerts): selected_id = int(self._home_alerts[current]["id"])
        self.home_alert_list.blockSignals(True); self.home_alert_list.clear()
        for record in self._home_alerts:
            symbol, _color, severity = self.level_style(record["severity"])
            self.home_alert_list.addItem(f"{symbol} {severity}  |  {record['title']}  |  {display_datetime(record['created_at'])}")
        self.home_alert_list.blockSignals(False)
        target = next((i for i, row in enumerate(self._home_alerts) if int(row["id"]) == selected_id), 0 if self._home_alerts else -1)
        self.home_alert_list.setCurrentRow(target)
        if not self._home_alerts: self.home_alert_detail.setPlainText("Nenhum alerta ativo no momento.")

    @staticmethod
    def make_table(headers, widths):
        table = QTableWidget(0, len(headers)); table.setHorizontalHeaderLabels(headers); table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows); table.setSelectionMode(QTableWidget.SingleSelection); table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.verticalHeader().setVisible(False); table.setShowGrid(True); table.setWordWrap(False); table.setSortingEnabled(True)
        header = table.horizontalHeader(); header.setStretchLastSection(True)
        for index, width in enumerate(widths[:-1]): table.setColumnWidth(index, width)
        return table

    def make_filters(self, alert: bool):
        frame = QFrame(objectName="toolbar"); row = QHBoxLayout(frame); row.setContentsMargins(6, 5, 6, 5)
        controls = {}
        controls["text"] = QLineEdit(); controls["text"].setPlaceholderText("Pesquisar texto...")
        controls["event_id"] = QLineEdit(); controls["event_id"].setPlaceholderText("Event ID"); controls["event_id"].setMaximumWidth(90)
        controls["level"] = QComboBox(); controls["level"].addItems(["TODOS"] + SEVERITIES)
        controls["provider"] = QLineEdit(); controls["provider"].setPlaceholderText("Provedor"); controls["provider"].setMaximumWidth(160)
        controls["category"] = QComboBox()
        if alert:
            controls["category"].addItems(["TODAS"] + sorted({rule[4] for rule in DEFAULT_RULES}))
        else:
            controls["category"].addItems(["TODAS", "Defender Operational", "Defender - eventos relevantes", "SENSE Operational", "PowerShell Operational", "Windows PowerShell", "Task Scheduler", "Sessões locais e remotas", "Criação de processos - evento 4688", "Segurança do Windows", "Outros eventos"])
        controls["category"].setMaximumWidth(235)
        controls["state"] = QComboBox(); controls["state"].addItems(["TODOS"] + ALERT_STATES); controls["state"].setVisible(alert)
        controls["period"] = QComboBox(); controls["period"].addItems(["TODOS", "24 HORAS", "7 DIAS", "30 DIAS", "PERSONALIZADO"])
        controls["since"] = QDateTimeEdit(QDateTime.currentDateTime().addDays(-1)); controls["since"].setCalendarPopup(True); controls["since"].setDisplayFormat("dd/MM/yyyy HH:mm"); controls["since"].setVisible(False)
        controls["period"].currentTextChanged.connect(lambda value: controls["since"].setVisible(value == "PERSONALIZADO"))
        for control in controls.values(): row.addWidget(control)
        kind = "alerts" if alert else "events"
        apply_button = QPushButton("[ FILTRAR ]"); apply_button.setIcon(font_icon("search")); apply_button.clicked.connect(lambda: self.apply_filters(kind)); row.addWidget(apply_button)
        controls["text"].returnPressed.connect(lambda: self.apply_filters(kind)); controls["event_id"].returnPressed.connect(lambda: self.apply_filters(kind)); controls["provider"].returnPressed.connect(lambda: self.apply_filters(kind))
        clear_button = QPushButton("[ LIMPAR ]"); clear_button.setIcon(font_icon("clear")); clear_button.clicked.connect(lambda: self.clear_filters(kind)); row.addWidget(clear_button)
        return frame, controls

    def make_pager(self, kind: str):
        frame = QFrame(objectName="toolbar"); row = QHBoxLayout(frame); row.setContentsMargins(6, 3, 6, 3); row.addStretch()
        previous = QPushButton("< ANTERIOR"); label = QLabel("PÁGINA 1"); following = QPushButton("PRÓXIMA >")
        previous.clicked.connect(lambda: self.change_page(kind, -1)); following.clicked.connect(lambda: self.change_page(kind, 1))
        row.addWidget(previous); row.addWidget(label); row.addWidget(following); row.addStretch()
        return frame, label, previous, following

    @staticmethod
    def section_list():
        widget = QListWidget(); widget.setMinimumWidth(235); widget.setMaximumWidth(330); widget.setAlternatingRowColors(True)
        return widget

    def make_alerts_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab); layout.setContentsMargins(0, 0, 0, 0)
        filters, self.alert_filters = self.make_filters(True); layout.addWidget(filters)
        split = QSplitter(Qt.Horizontal)
        self.alert_sections = self.section_list(); self.alert_view = self.viewer()
        split.addWidget(self.alert_sections); split.addWidget(self.alert_view); split.setSizes([280, 1120]); layout.addWidget(split, 1)
        actions = QFrame(objectName="toolbar"); action_row = QHBoxLayout(actions); action_row.setContentsMargins(6, 4, 6, 4)
        action_row.addWidget(QLabel("CATEGORIA SELECIONADA:"))
        read_button = QPushButton("[ MARCAR COMO LIDOS ]"); read_button.setIcon(font_icon("status")); read_button.clicked.connect(lambda: self.set_selected_alert_state("resolvido")); action_row.addWidget(read_button)
        ignore_button = QPushButton("[ IGNORAR ]"); ignore_button.setIcon(font_icon("alerts", "#FBBF24")); ignore_button.clicked.connect(lambda: self.set_selected_alert_state("ignorado")); action_row.addWidget(ignore_button)
        remove_button = QPushButton("[ REMOVER ]"); remove_button.setIcon(font_icon("delete", "#FB7185")); remove_button.clicked.connect(self.remove_selected_alerts); action_row.addWidget(remove_button)
        action_row.addStretch(); layout.addWidget(actions)
        pager, self.alert_page_label, self.alert_prev, self.alert_next = self.make_pager("alerts"); layout.addWidget(pager)
        return self.alert_sections, self.alert_view, tab

    def make_events_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab); layout.setContentsMargins(0, 0, 0, 0)
        filters, self.event_filters = self.make_filters(False); layout.addWidget(filters)
        split = QSplitter(Qt.Horizontal)
        self.event_sections = self.section_list(); self.event_view = self.viewer()
        split.addWidget(self.event_sections); split.addWidget(self.event_view); split.setSizes([280, 1120]); layout.addWidget(split, 1)
        pager, self.event_page_label, self.event_prev, self.event_next = self.make_pager("events"); layout.addWidget(pager)
        return self.event_sections, self.event_view, tab

    def make_settings_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab); layout.setContentsMargins(24, 20, 24, 20)
        title = QLabel(f"{APP_NAME}\nVersão {APP_VERSION}"); title.setAlignment(Qt.AlignCenter); layout.addWidget(title)
        settings_box = QGroupBox("CONFIGURAÇÕES DO WSAC"); form = QFormLayout(settings_box)
        self.interval = QSpinBox(); self.interval.setRange(1, 1440); self.interval.setValue(int(self.db.get_setting("monitor_interval_minutes", "5"))); self.interval.setSuffix(" min")
        self.lookback = QSpinBox(); self.lookback.setRange(5, 10080); self.lookback.setValue(int(self.db.get_setting("event_lookback_minutes", "30"))); self.lookback.setSuffix(" min")
        self.notify_severity = QComboBox(); self.notify_severity.addItems(SEVERITIES); self.notify_severity.setCurrentText(self.db.get_setting("notify_severity", "ALTO"))
        self.retention_days = QSpinBox(); self.retention_days.setRange(1, 3650); self.retention_days.setValue(int(self.db.get_setting("retention_days", "180"))); self.retention_days.setSuffix(" dias")
        self.max_db_mb = QSpinBox(); self.max_db_mb.setRange(10, 10240); self.max_db_mb.setValue(int(self.db.get_setting("max_db_mb", "500"))); self.max_db_mb.setSuffix(" MB")
        self.minimize_tray_check = QCheckBox("Ocultar da barra de tarefas ao minimizar"); self.minimize_tray_check.setChecked(self.db.get_setting("minimize_to_tray", "1") == "1")
        self.start_monitor_check = QCheckBox("Iniciar monitoramento ao abrir o WSAC"); self.start_monitor_check.setChecked(self.db.get_setting("start_monitoring", "0") == "1")
        form.addRow("Intervalo de monitoramento:", self.interval); form.addRow("Janela de busca de eventos:", self.lookback)
        form.addRow("Notificar a partir de:", self.notify_severity); form.addRow("Retenção do banco:", self.retention_days); form.addRow("Tamanho máximo do SQLite:", self.max_db_mb)
        form.addRow("", self.minimize_tray_check); form.addRow("", self.start_monitor_check)
        save = QPushButton("[ SALVAR CONFIGURAÇÕES ]"); save.clicked.connect(self.save_settings); form.addRow("", save); layout.addWidget(settings_box)
        rules_box = QGroupBox("REGRAS CONFIGURÁVEIS"); rules_layout = QVBoxLayout(rules_box); self.rule_widgets = []
        for rule in self.db.rules():
            row = QHBoxLayout(); enabled = QCheckBox(rule["title"]); enabled.setChecked(bool(rule["enabled"])); severity = QComboBox(); severity.addItems(SEVERITIES); severity.setCurrentText(rule["severity"])
            row.addWidget(enabled, 1); row.addWidget(severity); rules_layout.addLayout(row); self.rule_widgets.append((rule["rule_key"], enabled, severity))
        layout.addWidget(rules_box); layout.addStretch(); return tab

    @staticmethod
    def viewer():
        view = QPlainTextEdit(); view.setReadOnly(True); view.setFont(QFont("Consolas", 9)); view.setLineWrapMode(QPlainTextEdit.WidgetWidth); return view

    def install_tab_shortcuts(self):
        for index in range(self.tabs.count()):
            shortcut = QShortcut(QKeySequence(f"Ctrl+{index + 1}"), self); shortcut.activated.connect(lambda i=index: self.tabs.setCurrentIndex(i)); setattr(self, f"_tab_shortcut_{index}", shortcut)

    @staticmethod
    def make_security_icon(state: str = "green") -> QIcon:
        sprite = QPixmap(128, 128); sprite.fill(Qt.transparent)
        painter = QPainter(sprite); painter.setRenderHint(QPainter.Antialiasing)
        palette = {"red": "#FB7185", "yellow": "#FBBF24", "blue": "#22D3EE", "green": "#4ADE80", "gray": "#94A3B8"}
        accent = QColor(palette.get(state, palette["green"]))
        painter.setPen(Qt.NoPen)

        if state == "red":
            # A hot flame silhouette sits behind a simple upright sword.
            flame = QPainterPath(); flame.moveTo(64, 116)
            flame.cubicTo(36, 105, 20, 89, 25, 69); flame.cubicTo(28, 57, 40, 51, 37, 37)
            flame.cubicTo(50, 42, 55, 53, 54, 63); flame.cubicTo(63, 49, 66, 32, 63, 14)
            flame.cubicTo(82, 30, 79, 47, 77, 60); flame.cubicTo(84, 50, 93, 45, 102, 43)
            flame.cubicTo(96, 60, 106, 68, 103, 84); flame.cubicTo(100, 101, 84, 111, 64, 116)
            flame.closeSubpath(); painter.setBrush(QColor("#F97316")); painter.drawPath(flame)

            core = QPainterPath(); core.moveTo(64, 105)
            core.cubicTo(48, 97, 39, 87, 44, 72); core.cubicTo(50, 77, 54, 84, 56, 91)
            core.cubicTo(56, 74, 66, 59, 66, 47); core.cubicTo(79, 62, 75, 77, 81, 87)
            core.cubicTo(85, 81, 89, 76, 92, 73); core.cubicTo(94, 88, 83, 101, 64, 105)
            core.closeSubpath(); painter.setBrush(QColor("#FBBF24")); painter.drawPath(core)

            blade = QPainterPath(); blade.moveTo(64, 13); blade.lineTo(79, 69); blade.lineTo(64, 62); blade.lineTo(49, 69); blade.closeSubpath()
            painter.setBrush(QColor("#E2E8F0")); painter.drawPath(blade)
            highlight = QPainterPath(); highlight.moveTo(64, 22); highlight.lineTo(66, 63); highlight.lineTo(58, 66); highlight.closeSubpath()
            painter.setBrush(QColor("#FFFFFF")); painter.drawPath(highlight)

            guard = QPainterPath(); guard.moveTo(43, 68); guard.lineTo(63, 76); guard.lineTo(85, 68)
            guard.lineTo(92, 75); guard.lineTo(65, 84); guard.lineTo(37, 75); guard.closeSubpath()
            painter.setBrush(QColor("#F8FAFC")); painter.drawPath(guard)
            painter.setBrush(QColor("#475569")); painter.drawRoundedRect(60, 80, 8, 29, 3, 3)
            painter.setBrush(QColor("#CBD5E1")); painter.drawEllipse(57, 104, 14, 14)
        else:
            shield = QPainterPath(); shield.moveTo(64, 12); shield.cubicTo(80, 22, 96, 27, 109, 29)
            shield.lineTo(107, 67); shield.cubicTo(106, 88, 88, 105, 64, 117)
            shield.cubicTo(40, 105, 22, 88, 21, 67); shield.lineTo(19, 29)
            shield.cubicTo(32, 27, 48, 22, 64, 12); shield.closeSubpath()
            painter.setBrush(QColor("#172554" if state == "blue" else "#14251F"))
            painter.setPen(QPen(accent, 6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)); painter.drawPath(shield)
            if state == "green":
                painter.setPen(QPen(QColor("#BBF7D0"), 7, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
                painter.drawLine(43, 65, 57, 79); painter.drawLine(57, 79, 85, 49)
        painter.end()
        return QIcon(sprite)

    def set_signal(self, text: str, color: str):
        colors = {"green": "#60A5FA", "yellow": "#FBBF24", "red": "#FB7185", "blue": "#22D3EE", "gray": "#94A3B8"}
        icon = self.make_security_icon(color); self.signal_dot.setPixmap(icon.pixmap(34, 34)); self.signal_dot.setToolTip(f"Estado: {text}")
        self.signal_text.setStyleSheet(f"color:{colors[color]}"); self.signal_text.setText(text)
        if self.tray: self.tray.setIcon(icon); self.tray.setToolTip(f"{APP_NAME} | {text}")

    def setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable(): return
        self.tray = QSystemTrayIcon(self.make_security_icon(), self)
        menu = QMenu(); show_action = QAction("Abrir WSAC", self); show_action.triggered.connect(self.restore_window); menu.addAction(show_action)
        collect_action = QAction("Coletar agora", self); collect_action.triggered.connect(self.start_collection); menu.addAction(collect_action)
        monitor_action = QAction("Iniciar / parar monitoramento", self); monitor_action.triggered.connect(self.toggle_monitor); menu.addAction(monitor_action)
        menu.addSeparator(); exit_action = QAction("Encerrar WSAC", self); exit_action.triggered.connect(self.exit_application); menu.addAction(exit_action)
        self.tray.setContextMenu(menu); self.tray.activated.connect(self.tray_activated); self.tray.show()

    @Slot(QSystemTrayIcon.ActivationReason)
    def tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick): self.restore_window()

    def restore_window(self):
        self.showNormal(); self.show(); self.raise_(); self.activateWindow()

    def filter_values(self, kind: str) -> dict:
        controls = self.alert_filters if kind == "alerts" else self.event_filters; result = {}
        for key in ("text", "provider"):
            value = controls[key].text().strip()
            if value: result[key] = value
        category = controls["category"].currentText()
        if category not in {"TODAS", "TODOS"}: result["category"] = category
        event_id = controls["event_id"].text().strip()
        if event_id.isdigit(): result["event_id"] = int(event_id)
        if controls["level"].currentText() != "TODOS": result["level"] = controls["level"].currentText()
        if kind == "alerts" and controls["state"].currentText() != "TODOS": result["state"] = controls["state"].currentText()
        period = controls["period"].currentText(); now = dt.datetime.now().astimezone()
        days = {"24 HORAS": 1, "7 DIAS": 7, "30 DIAS": 30}.get(period)
        if days: result["from"] = (now - dt.timedelta(days=days)).isoformat(timespec="seconds")
        elif period == "PERSONALIZADO": result["from"] = controls["since"].dateTime().toPython().astimezone().isoformat(timespec="seconds")
        return result

    def apply_filters(self, kind: str):
        if kind == "alerts": self.alert_page = 1
        else: self.event_page = 1
        self.refresh_all(); self.log_terminal(f"Filtros aplicados em {'alertas' if kind == 'alerts' else 'eventos'}.", "FILTRO")

    def clear_filters(self, kind: str):
        controls = self.alert_filters if kind == "alerts" else self.event_filters
        for key in ("text", "event_id", "provider"): controls[key].clear()
        controls["category"].setCurrentIndex(0); controls["level"].setCurrentIndex(0); controls["period"].setCurrentIndex(0); controls["state"].setCurrentIndex(0)
        self.apply_filters(kind)

    def change_page(self, kind: str, direction: int):
        if kind == "alerts": self.alert_page = max(1, self.alert_page + direction)
        else: self.event_page = max(1, self.event_page + direction)
        self.refresh_all()

    def selected_alert_ids(self) -> list[int]:
        category = self._selected_key(self.alert_sections)
        return [int(record["id"]) for record in self._alerts if record["category"] == category]

    def set_selected_alert_state(self, state: str):
        ids = self.selected_alert_ids()
        if not ids: self.log_terminal("Nenhum alerta disponível na categoria selecionada.", "AVISO"); return
        changed = self.db.update_alerts_state(ids, state)
        self.log_terminal(f"{changed} alerta(s) marcado(s) como {state}.", "ALERTA")
        self.refresh_all(); self.set_signal(*self.db.alert_mood())

    def remove_selected_alerts(self):
        ids = self.selected_alert_ids()
        if not ids: self.log_terminal("Nenhum alerta disponível na categoria selecionada.", "AVISO"); return
        category = self._selected_key(self.alert_sections)
        answer = QMessageBox.question(self, "Remover alertas", f"Remover permanentemente {len(ids)} alerta(s) da categoria '{category}'?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if answer != QMessageBox.Yes: return
        removed = self.db.delete_alerts(ids); self.log_terminal(f"{removed} alerta(s) removido(s) da categoria {category}.", "ALERTA")
        self.refresh_all(); self.set_signal(*self.db.alert_mood())

    def log_terminal(self, message: str, level: str = "INFO"):
        if not hasattr(self, "software_terminal"): return
        timestamp = dt.datetime.now().strftime("%H:%M:%S")
        self.software_terminal.appendPlainText(f"[{timestamp}] [{level}] {message}")
        bar = self.software_terminal.verticalScrollBar(); bar.setValue(bar.maximum())

    def save_settings(self):
        values = {
            "monitor_interval_minutes": self.interval.value(), "event_lookback_minutes": self.lookback.value(),
            "notify_severity": self.notify_severity.currentText(), "retention_days": self.retention_days.value(),
            "max_db_mb": self.max_db_mb.value(), "minimize_to_tray": 1 if self.minimize_tray_check.isChecked() else 0,
            "start_monitoring": 1 if self.start_monitor_check.isChecked() else 0,
        }
        for key, value in values.items(): self.db.set_setting(key, value)
        for key, enabled, severity in self.rule_widgets: self.db.update_rule(key, enabled.isChecked(), severity.currentText())
        self.db.cleanup(self.retention_days.value(), self.max_db_mb.value())
        if self.timer.isActive(): self.schedule_next_collection()
        self.footer.setText("CONFIGURAÇÕES SALVAS"); self.log_terminal("Configurações salvas e retenção do banco verificada.", "CONFIG")

    def changeEvent(self, event):
        if event.type() == QEvent.WindowStateChange and self.isMinimized() and self.minimize_tray_check.isChecked() and self.tray:
            QTimer.singleShot(0, self.hide)
            if not self._tray_notice_shown:
                self.tray.showMessage(APP_NAME, "O WSAC permanece ativo na bandeja do sistema.", QSystemTrayIcon.Information, 3000); self._tray_notice_shown = True
        super().changeEvent(event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_F5: self.start_collection(); return
        if event.key() == Qt.Key_F6: self.toggle_monitor(); return
        super().keyPressEvent(event)

    def schedule_next_collection(self):
        interval_ms = self.interval.value() * 60_000; self.timer.start(interval_ms)
        self.next_collection_at = dt.datetime.now() + dt.timedelta(milliseconds=interval_ms); self.countdown_timer.start(1000); self.update_countdown()

    def update_countdown(self):
        if not self.next_collection_at: return
        remaining = max(0, int((self.next_collection_at - dt.datetime.now()).total_seconds())); total = max(1, self.interval.value() * 60)
        self.countdown_bar.setValue(int(1000 * remaining / total)); self.countdown_label.setText(f"{remaining // 60:02d}:{remaining % 60:02d}")

    def toggle_monitor(self):
        if self.timer.isActive():
            self.timer.stop(); self.countdown_timer.stop(); self.next_collection_at = None; self.countdown_bar.setValue(0); self.countdown_label.setText("--:--")
            self.monitor_btn.setText("[ F6 ] INICIAR MONITORAMENTO"); self.set_signal(*self.db.alert_mood()); self.footer.setText("MONITORAMENTO INTERROMPIDO"); self.log_terminal("Monitoramento contínuo interrompido.", "MONITOR")
        else:
            self.schedule_next_collection(); self.monitor_btn.setText("[ F6 ] PARAR MONITORAMENTO"); self.set_signal(*self.db.alert_mood()); self.log_terminal(f"Monitoramento iniciado. Intervalo: {self.interval.value()} minuto(s).", "MONITOR"); self.start_collection()

    @Slot()
    def start_collection(self):
        if self.thread and self.thread.isRunning(): return
        self.run_id = self.db.begin_run("monitor" if self.timer.isActive() else "manual")
        self.run_btn.setEnabled(False); self.footer.setText("COLETA EM ANDAMENTO..."); self.log_terminal(f"Coleta iniciada. Janela consultada: {self.lookback.value()} minuto(s).", "COLETA")
        self.thread = QThread(self); self.worker = Collector(self.lookback.value()); self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run); self.worker.progress.connect(self.footer.setText); self.worker.completed.connect(self.collection_done); self.worker.failed.connect(self.collection_failed)
        self.worker.completed.connect(self.thread.quit); self.worker.failed.connect(self.thread.quit); self.thread.finished.connect(self.worker.deleteLater); self.thread.finished.connect(self.release_thread); self.thread.start()

    @Slot(object, object, object, object)
    def collection_done(self, statuses, events, errors, meta):
        new_events = new_alerts = changes = 0; new_severities = []
        # Todas as inserções/atualizações abaixo permanecem na mesma transação.
        # finish_run() realiza um único commit ao final do lote.
        inactive_rule = self.db.rule("security_component_stopped")
        for status in statuses:
            component, state, details = str(status.get("Component", "Desconhecido")), str(status.get("State", "Desconhecido")), str(status.get("Details", "") or "")
            if self.db.add_snapshot(self.run_id, component, state, details): changes += 1
            if state.lower() in {"stopped", "inativo", "parado"} and component in {"WinDefend", "Sense", "RealTimeProtectionEnabled", "AntivirusEnabled"} and inactive_rule and inactive_rule["enabled"]:
                alert = AlertRecord(inactive_rule["severity"], inactive_rule["privacy_relevance"], inactive_rule["category"], f"{component} está {state}", details)
                if self.db.insert_alert(None, alert): new_alerts += 1; new_severities.append(alert.severity)
        for event in events:
            event_db_id, inserted = self.db.insert_event(event)
            if inserted:
                new_events += 1
                for alert in classify_event(event, self.db):
                    if self.db.insert_alert(event_db_id, alert): new_alerts += 1; new_severities.append(alert.severity)
        self.db.finish_run(self.run_id, "partial" if errors else "completed", "\n".join(errors) if errors else None)
        self.db.cleanup(self.retention_days.value(), self.max_db_mb.value()); self.refresh_all(); self.run_btn.setEnabled(True)
        db_mb = self.db.path.stat().st_size / (1024 * 1024) if self.db.path.exists() else 0
        self.log_terminal(f"Armazenamento otimizado. Banco atual: {db_mb:.2f} MB.", "BANCO")
        if self.timer.isActive(): self.schedule_next_collection()
        mood_text, mood_color = self.db.alert_mood()
        self.set_signal(mood_text, mood_color)
        threshold = SEVERITY_RANK.get(self.notify_severity.currentText(), 2)
        relevant = [value for value in new_severities if SEVERITY_RANK.get(value, 0) >= threshold]
        if relevant and self.tray: self.tray.showMessage(APP_NAME, f"{len(relevant)} novo(s) alerta(s) relevante(s).", QSystemTrayIcon.Warning, 5000)
        collected_total = int(meta.get("event_count", len(events))) if isinstance(meta, dict) else len(events)
        error_summary = f" | {len(errors)} FONTE(S) COM ERRO" if errors else ""
        self.footer.setText(f"CONCLUÍDO | {collected_total} COLETADOS | {new_events} NOVOS | {new_alerts} ALERTAS | {changes} MUDANÇAS{error_summary} | {dt.datetime.now():%H:%M:%S}")
        self.log_terminal(f"Coleta concluída: {collected_total} coletados, {new_events} novos, {new_alerts} alertas e {changes} mudanças.", "COLETA")
        for source_error in errors: self.log_terminal(source_error, "ERRO")

    @Slot(str)
    def collection_failed(self, error):
        self.db.rollback()
        if self.run_id: self.db.finish_run(self.run_id, "failed", error)
        self.run_btn.setEnabled(True); self.set_signal(*self.db.alert_mood()); self.footer.setText(f"ERRO: {error}"); self.log_terminal(error, "ERRO"); QMessageBox.critical(self, "Falha na coleta", error)
        if self.timer.isActive(): self.schedule_next_collection()

    @Slot()
    def release_thread(self):
        if self.thread: self.thread.deleteLater()
        self.thread = self.worker = None

    @staticmethod
    def level_style(level: str):
        value = (level or "").upper()
        if value in {"CRÍTICO", "CRITICAL", "ERRO", "ERROR"}: return "◆", QColor("#FB7185"), "CRÍTICO"
        if value in {"ALTO", "WARNING", "AVISO"}: return "▲", QColor("#F97316"), "ALTO"
        if value in {"MÉDIO", "MEDIO"}: return "●", QColor("#FBBF24"), "MÉDIO"
        if value in {"INFORMATIVO", "INFORMATION", "INFORMAÇÕES", "INFORMACAO", "INFORMAÇÃO"}: return "■", QColor("#60A5FA"), "INFORMATIVO"
        return "◇", QColor("#DCE6F3"), value or "SEM NÍVEL"

    @staticmethod
    def put_row(table, row, values, color=None):
        table.insertRow(row)
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value or "")); item.setToolTip(str(value or ""))
            if color: item.setForeground(color)
            table.setItem(row, column, item)

    @staticmethod
    def _selected_key(widget: QListWidget) -> str:
        item = widget.currentItem()
        return str(item.data(Qt.UserRole)) if item else ""

    @staticmethod
    def _fill_sections(widget: QListWidget, records, selected: str, category_field: str = "category"):
        counts = {}
        scroll_position = widget.verticalScrollBar().value()
        for record in records:
            key = str(record[category_field] or "Sem classificação")
            counts[key] = counts.get(key, 0) + 1
        widget.blockSignals(True); widget.clear()
        for key in sorted(counts, key=str.casefold):
            item = QListWidgetItem(f"{key} ({counts[key]})"); item.setData(Qt.UserRole, key)
            category_records = [record for record in records if str(record[category_field] or "Sem classificação") == key]
            if category_records and all("state" in record.keys() and record["state"] in {"resolvido", "ignorado"} for record in category_records):
                font = item.font(); font.setStrikeOut(True); item.setFont(font); item.setForeground(QColor("#94A3B8"))
            widget.addItem(item)
        target = 0
        if selected:
            for index in range(widget.count()):
                if widget.item(index).data(Qt.UserRole) == selected:
                    target = index; break
        if widget.count(): widget.setCurrentRow(target)
        widget.verticalScrollBar().setValue(min(scroll_position, widget.verticalScrollBar().maximum()))
        widget.blockSignals(False)

    def section_changed(self, kind: str, item):
        if item is None: return
        self.render_continuous(kind)

    @staticmethod
    def strike_text(value: object) -> str:
        return "".join(character + "\u0336" for character in str(value))

    def render_continuous(self, kind: str):
        if kind == "events":
            selected = self._selected_key(self.event_sections)
            records = [r for r in self._events if r["category"] == selected] if selected else []
            parts = []
            for record in records:
                parts.append(
                    f"SEÇÃO           : {record['category']}\n"
                    f"PRIMEIRA VEZ    : {display_datetime(record['created_at'])}\n"
                    f"ÚLTIMA VEZ      : {display_datetime(record['last_seen_at'])}\n"
                    f"OCORRÊNCIAS     : {record['occurrence_count']}\n"
                    f"EVENT ID        : {record['event_id']}\n"
                    f"NÍVEL           : {record['level'] or '-'}\n"
                    f"PROVEDOR        : {record['provider'] or '-'}\n"
                    f"LOG             : {record['log_name']}\n"
                    f"RECORD ID       : {record['record_id']}\n"
                    f"MENSAGEM        : {record['message'] or '-'}"
                )
            self.event_view.setPlainText(("\n\n" + "=" * 110 + "\n\n").join(parts) if parts else "Nenhum evento encontrado nesta classificação.")
        else:
            selected = self._selected_key(self.alert_sections)
            records = [r for r in self._alerts if r["category"] == selected] if selected else []
            parts = []
            for record in records:
                symbol, _color, label = self.level_style(record["severity"])
                read = record["state"] in {"resolvido", "ignorado"}
                source_event = record["source_event_id"] or "-"; provider = record["provider"] or "-"; log_name = record["log_name"] or "-"
                if read:
                    source_event = self.strike_text(source_event); provider = self.strike_text(provider); log_name = self.strike_text(log_name)
                parts.append(
                    f"{symbol} IMPORTÂNCIA : {label}\n"
                    f"DATA/HORA       : {display_datetime(record['created_at'])}\n"
                    f"CATEGORIA       : {record['category']}\n"
                    f"ESTADO          : {record['state'].upper()}\n"
                    f"PRIVACIDADE     : {record['privacy_relevance']}\n"
                    f"EVENT ID        : {source_event}\n"
                    f"PROVEDOR        : {provider}\n"
                    f"LOG DE ORIGEM   : {log_name}\n"
                    f"TÍTULO          : {record['title']}\n"
                    f"DETALHES        : {record['details']}"
                )
            self.alert_view.setPlainText(("\n\n" + "=" * 110 + "\n\n").join(parts) if parts else "Nenhum alerta encontrado nesta classificação.")

    def refresh_all(self):
        selected_alert = self._selected_key(self.alert_sections)
        selected_event = self._selected_key(self.event_sections)
        alert_cursor = self.alert_view.textCursor().position(); alert_scroll = self.alert_view.verticalScrollBar().value()
        event_cursor = self.event_view.textCursor().position(); event_scroll = self.event_view.verticalScrollBar().value()
        self._alerts, total = self.db.query_alerts(self.filter_values("alerts"), self.alert_page, PAGE_SIZE)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE); self.alert_page = min(self.alert_page, pages)
        self._fill_sections(self.alert_sections, self._alerts, selected_alert)
        self.alert_page_label.setText(f"PÁGINA {self.alert_page} DE {pages} | {total} ALERTAS"); self.alert_prev.setEnabled(self.alert_page > 1); self.alert_next.setEnabled(self.alert_page < pages)
        self._events, total = self.db.query_events(self.filter_values("events"), self.event_page, PAGE_SIZE)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE); self.event_page = min(self.event_page, pages)
        self._fill_sections(self.event_sections, self._events, selected_event)
        self.event_page_label.setText(f"PÁGINA {self.event_page} DE {pages} | {total} EVENTOS"); self.event_prev.setEnabled(self.event_page > 1); self.event_next.setEnabled(self.event_page < pages)
        self.render_continuous("alerts"); self.render_continuous("events")
        self.alert_view.verticalScrollBar().setValue(min(alert_scroll, self.alert_view.verticalScrollBar().maximum()))
        self.event_view.verticalScrollBar().setValue(min(event_scroll, self.event_view.verticalScrollBar().maximum()))
        self.status_table.setSortingEnabled(False); self.status_table.setRowCount(0)
        for row, record in enumerate(self.db.current_status()):
            state = record["state"] or ""; low = state.lower()
            symbol, color = ("◆", QColor("#FB7185")) if low in {"stopped", "inativo", "parado"} else (("●", QColor("#FBBF24")) if low in {"não encontrado", "indisponível"} else ("■", QColor("#60A5FA")))
            self.put_row(self.status_table, row, [symbol, record["component"], state, display_datetime(record["observed_at"]), record["details"] or ""], color)
        self.status_table.setSortingEnabled(True); self.history_table.setSortingEnabled(False); self.history_table.setRowCount(0)
        for row, record in enumerate(self.db.history()):
            _symbol, color, _label = self.level_style("MÉDIO" if record["previous_state"] != record["current_state"] else "INFORMATIVO")
            self.put_row(self.history_table, row, [display_datetime(record["observed_at"]), record["component"], record["previous_state"], record["current_state"], record["details"] or ""], color)
        self.history_table.setSortingEnabled(True)
        self.refresh_home()

    def show_alert(self, index):
        self.render_continuous("alerts")

    def show_event(self, index):
        self.render_continuous("events")

    def exit_application(self):
        if self.thread and self.thread.isRunning(): QMessageBox.information(self, "Coleta em andamento", "Aguarde a conclusão da coleta."); return
        self.timer.stop(); self.countdown_timer.stop()
        if self.tray: self.tray.hide()
        self.db.close(); QApplication.quit()

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning(): QMessageBox.information(self, "Coleta em andamento", "Aguarde a conclusão da coleta."); event.ignore(); return
        self.timer.stop(); self.countdown_timer.stop()
        if self.tray: self.tray.hide()
        self.db.close(); event.accept()


def main() -> int:
    if os.name != "nt": raise SystemExit("Este aplicativo foi desenvolvido para Windows.")
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setStyle("Fusion"); apply_palette(app, QPalette, QColor); app.setStyleSheet(STYLE)
    window = MainWindow(); window.show(); return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
