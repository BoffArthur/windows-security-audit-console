# Windows Security Audit Console (WSAC)

Aplicativo desktop local de auditoria e acompanhamento de segurança do Windows. Interface estilo terminal (tema verde) construída com PySide6/Qt que coleta, armazena e exibe eventos de segurança do sistema, gerando alertas baseados em regras configuráveis.

**Versão:** 1.8.0 · **Licença:** MIT · **Desenvolvido por:** Arthur Boff

## Requisitos

- Windows (coleta via PowerShell / Event Log)
- Python 3.x
- `pip install -r requirements.txt` (ver `requirements.txt` para a lista completa)

## Funcionalidades

### Coleta (Collector, em thread separada)
- **Status de serviços:** `Sense`, `WinDefend`, `WdNisSvc`
- **Status do Microsoft Defender:** `Get-MpComputerStatus` (antivírus, proteção em tempo real, behavior monitor, IOAV, NIS, última atualização de assinaturas)
- **Eventos** dos últimos N minutos (até 1000 por log):
  - Microsoft-Windows-Windows Defender/Operational
  - Microsoft-Windows-SENSE/Operational
  - Microsoft-Windows-PowerShell/Operational
  - Windows PowerShell
  - Microsoft-Windows-TaskScheduler/Operational
  - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
  - Security (apenas evento 4688 — criação de processos)

### Armazenamento
SQLite local (`windows_security_audit.sqlite3`) com tabelas `runs`, `events` (mensagens comprimidas com zlib, deduplicação por hash), `alerts`, `alert_rules`, `status_current`/`status_changes`, `app_state`. Retenção automática por categoria (7 a 90 dias) com VACUUM.

### Alertas (`classify_event`)
Regras baseadas em event_id/provedor/texto:
- **Defender:** detecção (1006/1116), resposta (1007/1117), falha de remediação (1118–1120), alteração de proteção (5001/5010/5012), alteração de config (5004/5007), evento 2050
- **Sessões remotas:** eventos 21/22/25 do TerminalServices-LSM
- **PowerShell suspeito:** evento 4104 contendo `downloadstring`, `invoke-expression`, `encodedcommand`, `frombase64string`
- Regras editáveis pelo usuário (severidade, habilitar/desabilitar) na aba de configurações

### Interface (6 abas)
- **Início** — visão rápida dos componentes de segurança e alertas ativos, com leitura individual de alerta
- **Alertas importantes** — consulta completa com filtros, paginação e histórico de estados
- **Eventos coletados** — com filtros e paginação
- **Status do sistema** — tabela completa dos componentes
- **Histórico** — com terminal lateral
- **Sobre / Configurações**

Monitoramento periódico com countdown, system tray, atalhos de teclado (F5 coletar, F6 monitorar, Ctrl+1..5 trocar de aba).

### Outros
- Detecção de execução como administrador
- Verificação de compatibilidade de schema do DB (recria tabelas incompatíveis automaticamente)
- Classificação de eventos por categoria e retenção diferenciada

## Execução

```bash
python windows_security_audit_console.py
```

## Estrutura do repositório

```
.
├── LICENSE
├── README.md
├── windows_security_audit_console.py
├── windows_security_audit.sqlite3
└── ui/
    ├── icons.py
    └── theme.py
```
