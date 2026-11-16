# NoisyTCP lab — CVE-2026-99288 (Linux kernel, pre-auth TCP)

Lab reproducer, instrumentation and measurements for **NoisyTCP** — a pre-auth
remote corruption in the Linux TCP stack, fixed by
[`4e2b3ef19e0e`](https://git.kernel.org/stable/c/4e2b3ef19e0e04adca38442f07dd6bc93c712bf1)
("inet: reject unhashed sockets during established lookups"), affects almost
every Linux distribution since 4.4.

> **Status (read this first).** The PoC drives every precondition of the bug and
> measures them on real hardware: SYN-cookie requests accepted by the target
> kernel (97% acceptance over 8.4M attempts), **99.99% ABA reuse** of a just-freed
> `request_sock` slab slot, RPS separating the lookup context from the
> free/realloc context, and the lookup returning pooled request sockets ~1x per
> attempt. It does **not** reproduce the final `NULL rsk_listener` panic: that
> needs the reader to be preempted inside a ~2 ns window, which bare metal does
> not provide (even with an emulated 8–16 µs hardirq freeze). See
> [§7](#7-режим-жертва--сам-хост-bare-metal) for the numbers and the reasoning.
> Treat this as a research/measurement artifact, not a working exploit.

**TL;DR** — `attacker/noisytcp.c` is a self-contained Linux PoC (raw sockets, no
dependencies) for the trigger described in the advisory: an established-ehash
lookup that races with `free(request_sock)` + `tcp_get_cookie_sock()` at the same
slab address. `jit/noisyjit.c` is lab instrumentation that emulates the vCPU
preemption a KVM guest gets for free. Every claim below is backed by counters
read from the target kernel (`/proc/net/netstat`, bpftrace).

---

## Repo layout

| Path | What |
|---|---|
| `attacker/noisytcp.c` | the PoC: raw IP/TCP, IPv4 fragmentation, SYN-cookie harvest, `race` and `tw` modes, `probe`/`verify`/`fragtest` diagnostics |
| `attacker/*.bt` | bpftrace: ABA slab reuse (`aba*.bt`), window detector `unhashed`/`null_listener` (`det.bt`), SYN-queue diagnostics |
| `jit/noisyjit.c`, `jit/Makefile` | kernel module: pinned hrtimer in hardirq that freezes a CPU for N µs — emulates vCPU preemption |
| `docker-compose.yml`, `victim/` | self-contained lab: nginx victim (backlog 8) + attacker container + kmsg monitor |
| `chost.yml`, `victim8081.py` | "victim = the host itself" mode: bridge without NAT, attacker container against the host kernel |
| `run.sh` | driver for the container lab (`up`/`probe`/`verify`/`trace`/`race`/`down`) |
| `results/` | raw run logs used as evidence |

## Quick start (container lab, no host changes)

```bash
./run.sh build && ./run.sh up
./run.sh verify          # full SYN-cookie cycle, checked against the victim's counters
./run.sh race            # the race loop
```

Requires Docker; the victim container needs RPS writable (`privileged: true`).

## Responsible use

Everything here refuses targets outside loopback/RFC1918 and is meant for
laboratories you own. The vulnerability is patched (`7.3.4+`, `6.18.63+`,
`6.12.117+`); a hit panics the machine, i.e. it is a DoS, not RCE. If your kernel
is older, either update it, or set `net.ipv4.tcp_syncookies=0` in **every** netns,
or keep a single RX queue with RPS/RFS disabled (that is mitigation #2 and was
what protected the test bench before it was weakened on purpose).

---

## Українською

Локальна лабораторія для відтворення та вимірювання **NoisyTCP** — pre-auth
remote corruption у TCP-стеку Linux, виправленої комітом
[`4e2b3ef19e0e`](https://git.kernel.org/stable/c/4e2b3ef19e0e04adca38442f07dd6bc93c712bf1)
(«inet: reject unhashed sockets during established lookups»).

Усе, що робить цей PoC, обмежено локальною Docker-мережею: інструмент
відмовляється працювати з адресами, що не є loopback/RFC1918. Це
дослідницький стенд, не інструмент для атак.

---

## 1. Суть вразливості

`__inet_lookup_established()` шукає сокет у ehash без блокувань. Після збігу
4-tuple він бере референс і **повторно** перевіряє tuple, але не перевіряє, чи
новий об'єкт узагалі ще в хеші:

```c
sk_nulls_for_each_rcu(sk, node, &head->chain) {
        if (sk->sk_hash != hash)
                continue;
        if (likely(inet_match(net, sk, acookie, ports, dif, sdif))) {
                if (unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))   /* <-- RMW */
                        goto out;
                if (unlikely(!inet_match(net, sk, acookie, ports, dif, sdif))) {
                        sock_gen_put(sk);
                        goto begin;
                }
                goto found;            /* може повернути unhashed-об'єкт */
        }
}
```

Слаб request-сокетів має `SLAB_TYPESAFE_BY_RCU`: адреса звільненого об'єкта
одразу повертається у per-CPU freelist і може бути видана наступній алокації.
Тому між завантаженням вказівника й `refcount_inc_not_zero()` стара адреса може
встигнути стати **новим** об'єктом із тим самим 4-tuple. Патч додає перевірку
`hlist_nulls_unhashed_lockless(&sk->sk_nulls_node)`.

Найгірший варіант — коли новий об'єкт це request-сокет, створений
`tcp_get_cookie_sock()` для SYN-cookie:

* він **не вставлений** у ehash (`rsk_node.pprev == NULL`);
* у нього `rsk_listener == NULL` (`inet_reqsk_alloc(ops, sk, false)`);
* refcount уже 1 (виставлений при алокації й повторно в `tcp_get_cookie_sock`),
  тому `refcount_inc_not_zero()` успішний, а повторний `inet_match()` проходить —
  tuple ж той самий.

Далі `tcp_v4_rcv()`:

```c
if (sk->sk_state == TCP_NEW_SYN_RECV) {
        req = inet_reqsk(sk);
        sk  = req->rsk_listener;      /* NULL */
        if (!xfrm4_policy_check(sk, ...))   /* / tcp_inbound_hash(sk, ...) */
```

— читання `NULL->sk_state` (offset `0x12`, саме та адреса з advisory) у
softirq → `Kernel panic - not syncing: Fatal exception in interrupt`.
Сервіс у контейнері кладе весь хост, бо падає ядро.

---

## 2. Як це тригерить PoC

Потрібні чотири речі, і кожна з них у `attacker/noisytcp.c` реалізована явно:

| # | Що потрібно | Як робиться |
|---|---|---|
| 1 | Хешований request-сокет **R** для tuple **T** | `SYN(T)` коли в SYN-черзі є місце → `inet_csk_reqsk_queue_hash_add()` |
| 2 | Валідний SYN-cookie **C** для того ж **T** | `SYN(T)` коли SYN-черга заповнена (`backlog`), `tcp_syncookies=1` → `cookie_init_sequence()`; cookie живе ~120 с |
| 3 | Звільнити **R** і перевиділити його slab-слот cookie-request'ом | `RST(T)` з `seq = rcv_nxt` (in-window, інакше буде challenge ACK) → `inet_csk_reqsk_queue_drop()` + `kmem_cache_free`; потім `ACK` з валідним **C** → `cookie_v4_check()` → `tcp_get_cookie_sock()` → `inet_reqsk_alloc()` бере **той самий** слот (per-CPU freelist LIFO) |
| 4 | Паралельний lookup того ж **T** у **іншому** RX-контексті | lookup-пакет ріжеться на 2 IPv4-фрагменти: у non-first фрагмента інший RPS-хеш, тому reassembly + TCP-обробка йдуть на іншому CPU, ніж plain-пакети кроку 3 |

Послідовність у часі (один «постріл», 4 пакети поспіль):

```
  frag0 ─────► (лежить у frag-черзі)
  frag1 ─────► CPU_B: reassembly → tcp_v4_rcv → __inet_lookup_established()
                                                  │  завантажив адресу R
                                                  │  inet_match() ✔
                                                  ╳  ← потрібна зупинка (µs)
  RST   ─────► CPU_A: unlink R (pprev=NULL) → kmem_cache_free(R)
                                                  │
  ACK(C) ────► CPU_A: cookie_v4_check() → inet_reqsk_alloc() = та сама адреса,
                       refcount=1, unhashed, rsk_listener=NULL
                                                  │
                                        refcount_inc_not_zero() ✔
                                        inet_match() ✔  → повертає об'єкт
                                                  └─► tcp_v4_rcv: sk = NULL → panic
```

Ключове обмеження: між `inet_match()` і `refcount_inc_not_zero()` проходить
одиниці наносекунд. Щоб звільнення й перевиділення встигли туди потрапити,
виконання lookup **мусить** бути перерване на мікросекунди. У QEMU/KVM це дає
витискання vCPU гіпервізором (advisory: 5 с – 2 хв); на «тихому» bare-metal це
години.

---

## 3. Стенд

```
victim     nginx:alpine, listen 8080 backlog=8, syncookies=1,
           rps_cpus=fff на eth0 (щоб було >1 RX-контексту)
attacker   alpine + gcc; raw-сокети (IPPROTO_RAW / IPPROTO_TCP),
           SO_MARK=1 на своїх пакетах і iptables-правило, що гасить
           RST, які ядро саме генерує у відповідь на SYN-ACK
monitor    privileged-контейнер, безперервно читає /dev/kmsg → results/kmsg.log
           (переживає паніку ядра: рядки вже на диску)
```

Мережа `10.213.99.0/24` (щоб не перетнутися з іншими docker-мережами).

```bash
./run.sh build     # зібрати образи
./run.sh up        # підняти стенд + показати стан ядра/черги/RPS
./run.sh probe     # один raw SYN ↔ SYN-ACK
./run.sh verify    # повний cookie-цикл + лічильники жертви
./run.sh trace     # bpftrace: доказ ABA-перевикористання slab-слота
./run.sh race      # гонка (DURATION=120 BATCH=4 FREE_GAP=1 ALLOC_GAP=6 JITTER=6)
./run.sh down
```

`run.sh race` після прогону сам дивиться `results/kmsg.log` і каже, чи був
panic. Перед кожним прогоном жертву треба перезапускати (`docker compose restart
victim`): SYN-черга має починатися порожньою, інакше всі SYN ідуть cookie-шляхом
і request-сокет для tuple взагалі не створюється.

### Інструментація (`attacker/*.bt`)

* `aba.bt` — головний доказ: `__reqsk_free` + `inet_reqsk_alloc` показують
  перевиділення тієї самої адреси на тому самому CPU (`@aba_same_cpu`), а
  kretprobe на `__inet_lookup_established` ловить момент, коли lookup повернув
  **unhashed** `TCP_NEW_SYN_RECV` (`@unhashed`) і окремо — коли в нього
  `rsk_listener == NULL` (`@unhashed_null_listener`, це вже прекурсор паніки).
* `diag.bt` / `diag3.bt` — перевірка, що lookup взагалі знаходить R
  (`@state[12]`), і куди йдуть керівні SYN (cookie vs `hash_add`).

---

## 4. Результати на Docker Desktop (macOS, arm64)

Ядро VM: **7.0.14-linuxkit**, збірка 2026-10-30 → уражене (фікс у 7.3.4 /
6.18.63 / 6.12.117, 2026-11-03).

| Що виміряно | Значення |
|---|---|
| cookie-цикл | `TcpExtSyncookiesSent` росте, `SyncookiesRecv` ≈ **1 на спробу** (cookie-ACK справді доходить до `tcp_get_cookie_sock`) |
| звільнення R | `TcpExtEmbryonicRsts` росте на кількість in-window RST |
| ABA slab-слота | фінальний прогін 60 с: `aba_same_cpu` = **3 033 293** із 3 707 858 звільнень (**81.8 %**); прогін 120 с: 8.35 млн із 10.86 млн (77 %) — решта це `aba_other_cpu` |
| lookup знаходить R | `__inet_lookup_established` → `skc_state == TCP_NEW_SYN_RECV` ≈ **1.7 на спробу** (reader + RST) |
| RPS-розведення | plain-пакети фіксованого tuple → **лише CPU 2** (1213 із 1213 обробок); фрагментовані → розкид по CPU 0–11 |
| швидкість | 12 500–23 000 спроб/с (753 414 за 60 с; 2.76 млн за 120 с — залежить від навантаження хоста) |
| **вразливий lookup-return** | `@unhashed` = **3** за один прогін (535 тис. спроб) ⇒ ~5·10⁻⁶ на спробу; у всіх інших прогонах 0; `@unhashed_null_listener` = **0** |
| фінальний панік | **не відбувся**: 0 у `results/kmsg.log` за сумарно ~7 млн спроб |

### Чому крах не стався саме тут

`/proc/stat` у VM: `cpu … softirq 87163 **steal 0** …` — і до, і під час
навантаження 32 busy-loop'ами на хості. Тобто гіпервізор Docker Desktop
**не витискає vCPU**: кожен vCPU отримує свій core, `steal` нульовий, а
мікросекундних зупинок усередині softirq (крім таймерного тіка ~1–3 мкс) немає.
Тік покриває лише вузьке вікно «unlink → free» (це і є ті 3 `@unhashed`), але не
покриває «unlink → cookie-алокація» (~2–5 мкс), тому `rsk_listener` у
поверненого об'єкта ще не NULL.

Це збігається з advisory: на KVM/QEMU з preemption vCPU — 5 с–2 хв, на тихому
залізі — ~14 годин. Docker Desktop поводиться як «тихе залізо».

Виміряні артефакти прогонів лежать у `results/`:
`final_race.log`, `final_aba.txt` (метрики останнього прогону) і
`results/evidence/` (RPS-розведення по CPU, діагностика SYN-черги, сітка
таймінгів, прогін із трьома `@unhashed`).

### Щоб таки зловити панік

1. **KVM/QEMU VM** (не Docker Desktop), 2+ vCPU, і бажано перепідписаний хост
   (`steal > 0`) — тоді прогін має вкладатися в хвилини.
2. Довші прогони: `DURATION=1800 ./run.sh race` (при ~5·10⁻⁶/спроба і 2·10⁴
   спроб/с це очікувано десятки хвилин навіть без preemption).
3. Тюнінг таймінгу: `FREE_GAP`/`ALLOC_GAP`/`JITTER` (мікросекунди) і `BATCH`;
   `--noise N` додає RPS-трафік (у цьому ядрі не допомогло: RPS-IPI не виконує
   backlog всередині softirq, лише виставляє прапорець), `--stress N` — тиск на
   vCPU гостя.
4. На реальному сервері з кількома RX-чергами (`ethtool -l`) — не запускати
   взагалі: там падає хост.

---

## 5. Мітигації (з advisory)

1. Оновити ядро до `4e2b3ef19e0e` (7.3.4+ / 6.18.63+ / 6.12.117+).
2. Тимчасово: `sysctl -w net.ipv4.tcp_syncookies=0` — у **кожному** netns
   (у кожному контейнері з власною мережею). Ламає захист від SYN-flood.
3. Тимчасово: одна RX-черга + вимкнені RPS/RFS на інтерфейсі, куди приходять
   зовнішні пакети.

Перевірка, чи ви вражені: `uname -r` проти 7.3.4 / 6.18.63 / 6.12.117
(або наявність `hlist_nulls_unhashed_lockless` у `__inet_lookup_established` у
вашому дереві).

---

## 6. Обмеження

* PoC навмисно обмежений приватними адресами і не має функцій сканування,
  спуфінгу чужого трафіку чи розгону (amplification).
* «Безпечний» варіант умови (`unhashed`, але з живим `rsk_listener`) теж
  фіксується патчем і спостерігається в лабораторії — це той самий баг, лише без
  NULL-deref.
* Падіння ядра VM Docker Desktop кладе **всі** контейнери на машині; тому
  `monitor` пише kmsg на диск, а стенд живе в окремій мережі.

---

## 7. Режим «жертва = сам хост» (bare metal)

Коли є root на тестовій машині, лабораторію можна розгорнути **на ній самій**, і
тоді жертвою стає її ядро (падає вся машина, як у advisory). Для цього є
`chost.yml`: атакувальник у bridge-мережі **без masquerade** (щоб NAT не
переписував seq/ack), а ціль — служба самого хоста (`sshd:22` або власний
листенер).

```bash
# на хості-жертві
python3 - <<'EOF'
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 8081)); s.listen(8)          # backlog 8
while True:
    c, _ = s.accept(); c.close()                # accept+close: тримає accept-чергу порожньою
EOF
sudo sh -c 'echo f > /sys/class/net/vethXXXX/queues/rx-0/rps_cpus'   # RPS на host-side veth
sudo sysctl -w kernel.panic=10                                        # авто-reboot
docker compose -f chost.yml up -d
docker compose -f chost.yml exec attacker /poc/noisytcp \
    --victim <host-ip> --port 8081 --backlog 8 --batch 8 \
    --free-gap-us 0 --alloc-gap-us 0 --jitter-us 2 --mode race
```

### Що виміряно на `6.18.50+rpt-rpi-v8` (Debian 13, rpi400)

| Ланка | Результат |
|---|---|
| версія ядра | 6.18.50 < 6.18.63 → **вразливе**, фікса в Debian немає |
| cookie-цикл (лічильники хоста) | `SyncookiesSent` 8.39 млн, `SyncookiesRecv` 8.17 млн (**97.4 %**), `EmbryonicRsts` 33.4 млн |
| RPS-розведення | plain-пакети tuple → **CPU 3**, фрагментовані → **CPU 0** |
| ABA slab-слота | **41 367 із 41 372 (99.99 %)** звільнених слотів дістає наступна `inet_reqsk_alloc` на тому ж CPU |
| читання вікна | 15 % lookup'ів тривають 8–16 мкс під штучною preemption (модуль `noisyjit`), тобто зупинки реальні й довші за «free → alloc» |
| `unhashed` / `null_listener` | **0 / 0** |
| паніка | **не відтворена** на ~10 млн спроб (у т.ч. ~1.5 млн зі штучною preemption) |

### Точка краху на цьому ядрі (перевірено по сорсах 6.18.50)

```c
sk = req->rsk_listener;                        /* NULL для cookie-запиту */
if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb))     /* NULL → 1, не падає */
        drop_reason = SKB_DROP_REASON_XFRM_POLICY;
else
        drop_reason = tcp_inbound_hash(sk, req, skb, ...); /* без TCP-AO/MD5 безпечний */
...
if (unlikely(sk->sk_state != TCP_LISTEN)) {    /* NULL + 0x12  ← CR2 з advisory */
```

### Зсуви `struct sock_common` на цьому ядрі

Друкуються модулем `noisyjit` при завантаженні (BTF у rpt-ядра немає, тому
`det.bt` читає поля сирими кастами):

| поле | offset |
|---|---|
| `skc_state` | `0x12` |
| `skc_listener` | `0x60` |
| `skc_nulls_node` | `0x68` |
| `skc_nulls_node.pprev` | `0x70` |

### Інструментація вікна

* `attacker/det.bt` — `kretprobe:__inet_lookup_established` + сирі касти:
  рахує `state12`, `unhashed` (`pprev == 0`), `null_listener` (`pprev == 0 &&
  listener == 0`).
* `attacker/aba2.bt`, `aba3.bt` — ABA-перевикористання адреси (без типів):
  `__reqsk_free` на цьому ядрі не трасується, тому aba3 використовує
  `__inet_csk_reqsk_queue_drop`.
* `jit/noisyjit.c` — **лабораторний** емулятор vCPU-preemption: pinned hrtimer у
  hardirq, `period_us`/`burn_us`/`burn_cpu`. Морозити треба лише CPU reader'а:
  якщо морозити й CPU, що звільняє та перевиділяє слот, вікно роз'їжджається.
  (У завантаженому екземплярі після помилки в `jt_exit` модуль лишається з
  `refcnt=-1` — лікується ребутом; у коді вже виправлено.)


### 7a. Режим `tw`: `tcp_syncookies=2` + R через TIME_WAIT

Щоб прибрати з черги будь-який службовий трафік, є режим `--mode tw`. Він
потребує `net.ipv4.tcp_syncookies=2` (cookie для кожного SYN, SYN-черга завжди
порожня):

```
SYN(T)                    -> SYN-ACK з cookie C
ACK(ack=C+1)              -> handshake, дитина в accept-черзі
<чекаємо FIN>             -> listener зробив accept+close, сервер у FIN_WAIT_1
ACK(ack=F+1)              -> сервер у FIN_WAIT_2
FIN|ACK                   -> сервер у TIME_WAIT (окремим пакетом!)
<чекаємо ACK>             -> TW підтверджено
SYN(T, seq = s1+3)        -> TW поглинається, створюється хешований R
<гонка>                   -> frag-lookup vs RST(free R) + cookie ACK(realloc)
```

Три граблі, на які я наступив (усі виправлені в коді):

1. **ACK і FIN не можна слати одним пакетом** — у `tcp_fin()` це «поганий
   випадок» (`else if (th->fin || sock_owned_by_user(sk))`), TIME_WAIT
   відкладається на keepalive-таймер.
2. **ISN для конверсії має бути строго після `tw_rcv_nxt`**:
   `tcp_timewait_state_process()` конвертує лише за
   `after(TCP_SKB_CB(skb)->seq, rcv_nxt)`, тож `s2 = s1 + 2` (рівно `rcv_nxt`) і
   випадковий ISN не працюють — TIME_WAIT лишається і таблиця
   (`tcp_max_tw_buckets`, тут 16384) миттєво переповнюється.
3. **Backlog листенера = 8** (не 1): `sk_max_ack_backlog` обмежує і accept-чергу,
   а з backlog 1 `TcpExtListenOverflows` вибухає і R не створюється.

Виміряно на rpi400 (6.18.50): **2.2 тис. спроб/с**, `cookies == attempts`,
`time-wait = 0` (жодного накопичення), `state12` ≈ 0.9–1 на спробу (reader
справді знаходить R). З емуляцією preemption на CPU reader'а (8 мкс / 20 мкс):
`unhashed = 0`, паніки немає.

### Висновок по bare metal

Передумови виконані й виміряні, але останній кадр — зупинка рівно між
`inet_match()` і `refcount_inc_not_zero()` — не відтворився навіть зі штучними
зупинками 8–16 мкс. Практичні варіанти далі: (а) KVM/QEMU з `steal > 0` (за
advisory — 5 с–2 хв); (б) схема `tcp_syncookies=2` + створення R через
TIME_WAIT (без службового трафіку в черзі); (в) інструментація самого вікна
через модуль ядра з kprobe на конкретних інструкціях.
