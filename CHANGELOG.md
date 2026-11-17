# PortGuard Mini — Version History

Текущий релиз: **v0.8.4**.

Эта таблица фиксирует последовательность опубликованных этапов проекта. Старые версии сохраняются как история; текущую функциональность определяет последний релиз.

| Версия | Основное изменение |
| --- | --- |
| v0.1 | Первый минимальный hardening SSH/Apache/Nginx/PHP и команды `audit`, `apply`, `rollback`, `watch`. |
| v0.2 | `DebianBanner no` для OpenSSH, HTTP-header audit и baseline локальных TCP listeners. |
| v0.2.1 | Штатный systemd timer переведён на **read-only `audit`**; автоматический `apply` убран из периодической проверки. |
| v0.3 | Наблюдение за процессами и установленными TCP-соединениями. |
| v0.4 | Security inventory и `baseline-security` для выбранных SSH/sudoers/cron/systemd путей. |
| v0.5 | Отдельный Linux inotify watcher `portguard-event.service`. |
| v0.6 | Self-guard собственных служб и наблюдение успешных SSH-входов с необязательным списком доверенных IP. |
| v0.7 | `emergency-check` и отдельный **только ручной** `emergency-off POWER_OFF`. |
| v0.8 | Регистрация доверенного root SSH fingerprint и безопасный `emergency-simulate`. |
| v0.8.1 | Для audit-службы `ProtectHome` изменён на `read-only`, чтобы read-only проверка могла видеть `/root/.ssh`. |
| v0.8.2 | Исправлено штатное завершение inotify watcher при SIGTERM/systemd restart. |
| v0.8.3 | Точечные исправления `apply/rollback`, PHP-FPM validation, security inventory, baseline creation, watcher failure handling и установщиков без изменения архитектуры. |
| v0.8.4 | Исправлено распознавание активного Nginx `include /etc/nginx/conf.d/*.conf;` с пробелами/табами и комментариями. |

## Текущий статус

PortGuard Mini остаётся маленьким автономным помощником для Linux-сервера, а не IDS/IPS/SIEM/антивирусом. Основная схема: периодический read-only audit + отдельный необязательный inotify watcher. Конфигурационные `apply/rollback/watch` сохранены как legacy/manual paths и не запускаются штатным timer.

## Подробные заметки последних bugfix-релизов

- [v0.8.4](RELEASE-NOTES-v0.8.4-RU.md)
- [v0.8.3](RELEASE-NOTES-v0.8.3-RU.md)
- [v0.8.2](RELEASE-NOTES-v0.8.2-RU.md)
