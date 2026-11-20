# Пресс-релиз: dep-xray v0.1.0

**Дата:** 20 ноября 2026  
**Репозиторий:** https://github.com/markankamaransheogarat-sys/dep-xray  
**Лицензия:** MIT OR Apache-2.0  

## Заголовок
**dep-xray v0.1.0 — поведенческий AST-анализатор диффов зависимостей для защиты цепочки поставок (Cargo, npm, pnpm)**

## Ключевые возможности
- **AST-анализ на базе `tree-sitter`** для Rust (`build.rs`, `unsafe`-блоки, сетевые вызовы) и JS/TS (`postinstall`, `eval`, Base64).
- **Детектор энтропии и скрытых bidi-символов**.
- **Парсинг `Cargo.lock`, `package-lock.json` и `pnpm-lock.yaml`** с интеграцией в GitHub Action (`action.yml`).
- **Вывод в форматах Terminal, JSON, Markdown и SARIF**.
- **13/13 unit и integration тестов проходят**.
