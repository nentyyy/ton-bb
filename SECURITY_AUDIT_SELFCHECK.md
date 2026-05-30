# TON Security Audit — Self-Check / Само-проверка

**Репозиторий:** `nentyyy/ton-bb` @ `claude/ton-security-audit-iu1rW`
**Импортированный код:** upstream TON, commit `200a6e6794510be5d5faa83b15004bb3b135e7af` (побайтово)
**Дата:** 2026-05-30

---

## Вывод первой волны

> **NO VERIFIED HIGH-CONFIDENCE VULNERABILITY FOUND IN REVIEWED CODE.**

Подтверждённых эксплуатируемых уязвимостей (HIGH/CRITICAL) в проверенных поверхностях — **ноль**.

---

## Покрытие первой волны

| Компонент | Пути | Итог |
|-----------|------|------|
| ADNL + TL-десериализация | `adnl/*`, `tl/*`, `tl-utils/*`, `tdutils/.../tl_parsers`, Slice/buffer | чисто |
| Catchain + validator-session | `catchain/*`, `validator-session/*`, `crypto/block/signature-set.cpp` | чисто |
| TVM + BOC/cell | `crypto/vm/{boc.cpp,cells,stack,dict}`, `boc-compression.cpp` | чисто |
| Overlay/RLDP/RLDP2/DHT/FEC | `overlay/*`, `rldp/*`, `rldp2/*`, `dht/*`, `fec/*`, `tdfec/*` | чисто |
| Lite-server / external msg | `validator/impl/liteserver.cpp`, `external-message.cpp` | чисто |
| Декомпрессия lz4/boc | `tdutils/.../lz4.cpp`, `full-node-serializer.cpp` | чисто |

---

## Само-проверка вывода «багов не найдено»

### Где вывод устойчив
- Код побайтово = upstream `200a6e6` (сверено агентом ADNL). Это боевой код, годами проходящий багбаунти — низкая априорная вероятность свежего 0-day.
- Two-step FEC: лично прочитан `process_broadcast` + `Decoder::create/try_decode/add_symbol`; найден и проверен инвариант `seqno < persistent_node_count` (`overlay-peers.cpp:799`). Headline-сценарий субагента («1 broadcast → 462 МБ») **опровергнут** по коду, а не на доверии.
- lz4 / boc_decompress / liteserver / external-message — проверены лично по исходнику.

### Слабые места вывода (честно)
1. **Доверие субагентам.** По ADNL, catchain/validator-session и стандартному TVM приняты вердикты субагентов «safe» без полной личной перепроверки каждого отклонённого кандидата. Уверенность агента ≠ доказательство.
2. **Недочитанные пути.** В two-step FEC не дочитаны до конца `Rfc::get_parameters` и `Solver::run` (вывод про «аллокация только в try_decode» основан на прочтённой части конструктора).
3. **Непокрытые зоны.** Вердикт «чисто» относится ТОЛЬКО к проверенным поверхностям. НЕ исследованы:
   - `validator/impl/validate-query.cpp`, `collator-impl.cpp`, `accept-block.cpp`, `check-proof.cpp` (валидация блоков — крупнейшая логика)
   - `crypto/block/transaction.cpp`, `block.cpp`, `mc-config.cpp`
   - компилятор `tolk`, `crypto/func`, `crypto/fift`
   - `storage/*` (torrent), `tddb/*` (cell DB / snapshots)
   - QUIC / ngtcp2-интеграция

### Корректная формулировка
Не «в TON багов нет», а: **«в проверенном сетевом/консенсусном слое за этот проход эксплуатируемых HIGH/CRITICAL не обнаружено; значительная часть бизнес-логики ещё не исследована».**

---

## Отклонённые кандидаты (с причиной)

1. Negative `decompressed_size_` в candidate-serializer → `lz4_decompress` отвергает `<0` (`lz4.cpp:35`).
2. Forging signature-set → порог 2/3 + проверка vset + dedup + Ed25519 (`signature-set.cpp:89`).
3. Амплификация по `node_count` в BOC-декомпрессоре → лимит `2^20` и `≤ decompressed_size ≤ 16 МБ`.
4. Stack exhaustion в `build_node` → DP-страж `≥ max_depth(1024)` + инвариант `child > parent`.
5. Two-step FEC обход 16 МБ → ограничен `seqno < persistent_node_count`; не эксплуатируется.
6. `cell_count` overflow в `parse_serialized_header` → проверка `<=0`, арифметика в `unsigned long long`.

---

## Содержательное наблюдение (НЕ HIGH/CRITICAL)

`overlay/broadcast-twostep.cpp` (`process_broadcast` для `overlay_broadcastTwostepFec`, строки 367–415): RaptorQ-декодер строится напрямую из `data_size_`/`part_.size()`, минуя `fec::FecType::create` и `run_checks()` (лимит 16 МБ / `symbol_size ≤ 2048`) обычного FEC-пути. Практический потолок даёт `seqno < persistent_node_count`, поэтому это **defense-in-depth gap**, а не эксплуатируемая уязвимость.
**Рекомендация (hardening):** пропускать параметры через `FecType::create` + явный `max_fec_broadcast_size()`.

---

## Статус
- ✅ Волна 1 (сетевой/консенсусный слой) — завершена, находок HIGH/CRITICAL нет.
- 🔄 Волна 2 (валидация блоков, компиляторы, storage/DB) — запущена.
