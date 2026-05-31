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

## Волна 2 — результаты

### Реальная находка (LOW severity, ограниченная модель атакующего)
**Неограниченная рекурсия в парсерах Tolk и FunC → stack overflow (SIGSEGV / DoS).**
Recursive-descent без лимита глубины; ни в одном из компиляторов нет parser depth guard.
- Tolk: `tolk/ast-from-tokens.cpp` — `parse_expr75` (саморекурсия на унарных `! ~ - +`, строка 1304, **проверено лично**), `parse_expr100` (вложенные `(`, ~1113), `parse_type_expression`/`parse_nested_type_list` (вложенные `( [ <`, 271-321).
- FunC: `crypto/func/parse-func.cpp` — `parse_expr100` (438-469), `parse_type1` (72-130).
- Триггер: маленький исходник вида `return ----...----1;` или `var x = ((((...))));`.
- **Severity LOW в модели угроз TON:** компилятор — локальный CLI-инструмент разработчика, узлы/валидаторы НЕ компилируют недоверенный исходник в рантайме. Реальный риск только для хостящих контракт-верификаторов (server-side компиляция пользовательского кода) → перезапускаемый краш процесса, без повреждения памяти (guard page). Не consensus / не RCE.
- **Fix:** счётчик глубины разбора (или итеративный парсинг) в `parse_expr*` / `parse_type*`.

### Проверено лично и БЕЗОПАСНО
- **Storage path traversal (произвольная запись файла)** — `Torrent::get_chunk_path` склеивает имя из заголовка пира, НО `Torrent::set_header` (`Torrent.cpp:511`) вызывает `header.validate()` ДО записи, а `validate_name` (`TorrentHeader.cpp:69-97`) отвергает абсолютные пути, компоненты `.` и `..`, двойные слэши. Не эксплуатируется.
- Fift stack/tuple/bitstring примитивы — корректно ограничены (агент).

### НЕ завершено (лимит сессии субагента, требует следующего прохода)
- `validator/impl/validate-query.cpp`, `collator-impl.cpp`, `accept-block.cpp`, `check-proof.cpp`, `crypto/block/*` — **валидация блоков, самая важная логика, НЕ исследована.**
- `storage/*` (кроме проверенного path traversal), `tddb/*` (cell DB / snapshots) — не завершено.

## Волна 3 — валидация блоков (результаты)

### Проверено лично и БЕЗОПАСНО
- **`check-proof.cpp` + `signature-set.cpp`** — проверка block-proof/подписей надёжна: сверка catchain-seqno и hash набора валидаторов, Ed25519 над `to_sign = ton_blockId(root_hash, file_hash)` (связывает подпись с Merkle-корнем блока → нет replay на другой блок), порог 2/3 (`signature-set.cpp:89,155`), `virt_hash == proof_blk_id.root_hash` (`check-proof.cpp:152`).

### Кандидаты агентов — проверены и отклонены
- **Асимметрия в `check_one_shard` (`validate-query.cpp:2071-2076`)**: в null-ветке ShardFees проверяется только `fees_collected_.is_zero()`, но не `funds_created_`. **Лично верифицировано:** нейтрализуется `basic_info_equal(compare_fees=true)` (`mc-config.cpp:922`, сравнивает оба поля). Может лишь занизить `import_created`/global_balance, **детерминированно** для всех валидаторов → ни форка, ни инфляции, ни выгоды. Hardening-замечание (добавить `&& descr->funds_created_.is_zero()`), не эксплойт.
- **Signed-cast усечение fee/gas (`transaction.cpp:2881-2886, 3410-3411, 1304-1305`)**: `(long long)` каст uint64-значений; срабатывает только если fee/gas > 2^63, что достижимо **исключительно через враждебный masterchain-config** (привилегированный), не через пользовательское сообщение. Не user-triggerable.
- **Validator-set total_weight overflow (`mc-config.cpp:698-703`)**: защищён проверкой `descr.weight > ~total_weight` до `+=`. `compute_validator_set` индексы/веса — `CHECK`-guarded. Безопасно.
- **Per-transaction currency flow (`transaction.cpp:6111`)**: баланс из re-execution + сверка хэша транзакции, арифметика в `RefInt256`. Безопасно.
- **Рекурсия обхода shard-hash (`mc-config.cpp:1318`)**: ограничена битовой глубиной шарда (~60). Безопасно.

### Итог волны 3
Полностью вооружаемого fork / inflation / invalid-accept бага НЕ найдено. `validate-query.cpp` исключительно защитный: почти каждое поле кандидата независимо пересчитывается и сравнивается (транзакции переисполняются и сверяются по хэшу; value-flow реконсилируется; новое состояние выводится применением Merkle-update к проверенному предыдущему). Остаточные риски — config-gated усечения (привилегированный masterchain-config).

## Статус
- ✅ Волна 1 (сетевой/консенсусный слой) — HIGH/CRITICAL нет.
- ⚠️ Волна 2 — 1 реальный LOW-баг (рекурсия компиляторов Tolk/FunC); storage path-traversal безопасен.
- ✅ Волна 3 (валидация блоков, transaction/mc-config, proof/signature) — HIGH/CRITICAL нет; 1 hardening-асимметрия + config-gated усечения.
- ⬜ Не исследовано: `tddb/*` (cell DB / snapshots), QUIC.

## Перекрёстная верификация (Opus-перезапуск)

Агенты по `validate-query.cpp` и `crypto/block/*` были перезапущены с явным пином на Opus и **независимо сошлись** с первым проходом: HIGH/CRITICAL нет, те же guard'ы. Opus-агент дополнительно сделал git diff против импорт-коммита и подтвердил, что `transaction.cpp`/`block.cpp`/`mc-config.cpp` **побайтово идентичны upstream** (модификаций нет).

Остаточные не-эксплуатируемые наблюдения (для maintainers, не security):
- Мёртвый код после `return true` в `check_neighbor_outbound_message` (`validate-query.cpp:5253`) — все security-проверки f0-ветки выполняются ДО него; пропускается лишь избыточный internal `fatal_error`. Косметика.
- catch-блоки в `try_validate` (`validate-query.cpp:7594-7601`) ловят `vm::VmError`/`CellBuilder`, но не `std::out_of_range`/`std::bad_alloc`. Достижимого OOB-индекса не найдено, так что не эксплуатируется; но запас прочности узкий.

## Сводный вывод
**NO VERIFIED HIGH-CONFIDENCE VULNERABILITY FOUND IN REVIEWED CODE.**
Единственный подтверждённый реальный баг — неограниченная рекурсия парсеров Tolk/FunC (**LOW**, DoS только для server-side контракт-верификаторов). Всё остальное — либо защищено, либо требует привилегированного доступа (masterchain-config), либо детерминировано-безвредно.

Аудитом покрыты: ADNL/TL, catchain/validator-session, TVM/BOC, overlay/RLDP/RLDP2/DHT/FEC, lite-server/external-msg, декомпрессия, компиляторы (Tolk/FunC/Fift), storage/torrent, валидация блоков (validate-query/transaction/block/mc-config), proof/signature. Не покрыто: `tddb/*` (cell DB / snapshots), QUIC/ngtcp2.
