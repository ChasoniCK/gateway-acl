# План: переделка интерфейса панели в apple-like стиль

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Переписать слой представления `panel.py` — вид Настроек macOS вместо нынешней админки, без изменений в nftables, учёте трафика, установщике и подписке.

**Architecture:** Снизу вверх. Сначала токены и примитивы в `CSS`, потом блоки по одному переезжают на них. Панель работает и `--selftest` зелёный после каждой задачи. Смотреть на результат — через одноразовый стенд в скретчпаде, отдающий `render(PAGE_T)` и заглушку `/api`: панель без root не поднимается.

**Tech Stack:** Python 3 (только стандартная библиотека), HTML/CSS/JS строками внутри `panel.py`, inline SVG. Ни pip, ни npm, ни CDN.

**Spec:** [docs/superpowers/specs/2026-08-26-panel-redesign-design.md](../specs/2026-08-26-panel-redesign-design.md)

## Global Constraints

- **Только стандартная библиотека Python.** Ни одной зависимости, ни одного внешнего ресурса в странице: шлюз работает без интернета.
- **`VERSION` ([panel.py:62](../../../panel.py)) обязан равняться тегу релиза.** Бампится один раз, в последней задаче: `1.4.1` → `1.5.0`.
- **Ни одного цветового литерала вне блока токенов.** Исключение ровно одно — две меты `theme-color` в `HEAD`, которые переменную читать не умеют.
- **`--selftest` зелёный после каждой задачи.** Проверка: `python3 panel.py --selftest`.
- **Ничего не меняется** в `ruleset()`, `apply()`, учёте трафика, `check_settings()`, `config.json`, `install.sh`, `singbox_sub.py`, логике обновления, авторизации.
- **Правило шести мест** (CLAUDE.md) не задевается: тема живёт в localStorage и не является полем формы настроек.
- **README.md первичен, README.ru.md — полный перевод.** Пользовательские изменения нужны в обоих.
- **Ветка:** `panel-redesign`. Коммит на задачу, сообщения по-русски, как в истории репозитория.

## Карта файлов

| Файл | Что с ним | Ответственность |
|---|---|---|
| `panel.py` | правится | Единственный файл с кодом. Правки только в секции `# --- pages ---` ([panel.py:2104](../../../panel.py)), в `STRINGS` ([panel.py:197](../../../panel.py)) и в `selftest()` ([panel.py:3304](../../../panel.py)) |
| `docs/panel-ru.png`, `docs/panel-en.png` | перезаписываются | Скриншоты в README |
| `README.md`, `README.ru.md` | правятся | Описание интерфейса |
| `CLAUDE.md` | правится | Абзац про «переменные объявлены дважды» |
| `<скретчпад>/preview.py` | создаётся, **в репозиторий не идёт** | Стенд: `render(PAGE_T)` плюс заглушка `/api` |

Разбиение по функциям внутри `panel.py` не меняется: файл сознательно один, секционирован комментариями `# --- name ---`. Новые константы (`LIGHT`, `DARK`, `TOKENS`) кладутся рядом с `CSS`, перед ним.

## Соответствие этапам спеки

Спека называет девять этапов; план дробит их на двенадцать задач — граница проведена там, где результат можно принять или отвергнуть отдельно.

| Этап спеки | Задачи плана |
|---|---|
| — (стенд) | 1 |
| 1 токены и примитивы | 2 |
| 2 тема | 3 |
| 3 шапка, баннеры, шит | 4, 5 |
| 4 карточка трафика | 6, 7, 8 |
| 5 машина | 9 |
| 6 устройства | 10, 11 |
| 7 чужаки, конфликты, вход | 12 |
| 8 доки и скриншоты | 13 |
| 9 бамп версии | 14 |

---

### Task 1: Стенд для просмотра панели без root

**Files:**
- Create: `<скретчпад>/preview.py` (путь скретчпада этой сессии; **не** в репозиторий)

**Interfaces:**
- Consumes: `panel.render`, `panel.PAGE_T` из `panel.py`
- Produces: `http://127.0.0.1:8099` — та же страница, что видит браузер, с выдуманными данными. Все задачи ниже проверяются глазами через него.

- [ ] **Step 1: Написать стенд**

```python
#!/usr/bin/env python3
"""Панель без шлюза: настоящая страница, выдуманные данные.

Одноразовый инструмент для работы над вёрсткой. panel.py импортируется как
модуль — GWACL_DIR указывает в пустую папку, поэтому конфиг берётся из
DEFAULTS, а ни один вызов nft не случается: /api сюда не доходит.
"""
import json
import os
import sys
import time

os.environ.setdefault("GWACL_DIR", os.path.join(os.path.dirname(__file__), "etc"))
os.makedirs(os.environ["GWACL_DIR"], exist_ok=True)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__),
                                                "../../../../..")))
sys.argv = ["preview"]          # panel.main() не запускается, но argv читают

import panel                     # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

NOW = int(time.time())
DAYS = 31


def series(seed, n):
    """Пила с горбом посередине — на глаз похоже на живой трафик."""
    return [[int(3e8 + 2e8 * ((i * seed) % 7)), int(4e7 + 3e7 * ((i * seed) % 5))]
            for i in range(n)]


def device(ip, name, seed, on=True, seen=NOW, vpn=True, mac="c4:36:6c:11:8f:31"):
    ser = series(seed, DAYS)
    return {"ip": ip, "name": name, "on": on, "mac": mac, "host": "",
            "seen": seen, "until": 0, "vpn": vpn,
            "up": sum(d[1] for d in ser), "down": sum(d[0] for d in ser),
            "rate": [59600, 7300000] if seen == NOW else [0, 0],
            "series": ser, "hseries": series(seed, 24)}


STATE = {
    "month": time.strftime("%Y-%m"), "now": NOW, "poll": 5, "you": "192.168.1.42",
    "months": [[f"2025-{m:02d}", int(9e10 + m * 7e9)] for m in (9, 10, 11, 12)]
             + [[f"2026-{m:02d}", int(1e11 + m * 8e9)] for m in range(1, 9)],
    "prev": int(2.1e11), "update": "", "vpnable": True, "bypass": 0,
    "days": [[f"2026-08-{d:02d}", int(4e9 + d * 1e8), int(6e8)]
             for d in range(1, DAYS + 1)],
    "hours": [[f"{h:02d}", int(2e8 + h * 1e7), int(3e7)] for h in range(24)],
    "devices": [device("192.168.1.42", "Ноутбук", 3),
                device("192.168.1.51", "Телефон", 5, seen=NOW - 240),
                device("192.168.1.60", "Телевизор", 2, seen=NOW - 7200, vpn=False),
                device("192.168.1.71", "Рабочий ПК", 7),
                device("192.168.1.80", "Приставка", 4, on=False, seen=NOW - 172800)],
    "clash": [["192.168.1.60", "c4:36:6c:11:8f:31", "78:11:dc:9a:31:20", "Xiaomi"]],
    "blocked": [["192.168.1.113", "", "b8:27:eb:74:0d:15", 10800, "Raspberry Pi"],
                ["192.168.1.97", "esp-livingroom", "84:f3:eb:1c:90:22", 720,
                 "Espressif"]],
    "lan": [["192.168.1.56", "nas"], ["192.168.1.90", "printer"]],
    "sys": {"cpu": 11.4, "mem": [1300000000, 4070000000],
            "swap": [100663296, 2147483648], "disk": [6592000000, 29960000000],
            "iface": "eno1", "bps": [640000, 7300000], "load": [.34, .29, .31],
            "cores": 4, "temp": [46.0, "coretemp"], "up": 2019600},
}


class H(BaseHTTPRequestHandler):
    def _send(self, body, ctype="text/html; charset=utf-8"):
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/api"):
            self._send(json.dumps(STATE), "application/json")
        else:
            self._send(panel.render(panel.PAGE_T))

    def do_POST(self):        # кнопки нажимаются, ничего не происходит
        self._send("")

    do_DELETE = do_POST

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("http://127.0.0.1:8099")
    ThreadingHTTPServer(("127.0.0.1", 8099), H).serve_forever()
```

- [ ] **Step 2: Поднять и убедиться, что видна нынешняя панель**

```bash
python3 "$SCRATCH/preview.py"
```

Открыть `http://127.0.0.1:8099`. Ожидается сегодняшняя тёмная панель с пятью устройствами, графиком за август, конфликтом и двумя стучавшимися. Если страница пустая — смотреть консоль браузера: значит, `STATE` не совпал с тем, что ждёт `draw()`.

- [ ] **Step 3: Проверить, что репозиторий чист**

```bash
git status --short
```

Ожидается пустой вывод: стенд лежит в скретчпаде и в репозиторий не попадает. Коммита в этой задаче нет.

---

### Task 2: Токены и примитивы

**Files:**
- Modify: `panel.py` — `CSS` ([panel.py:2106](../../../panel.py)), `selftest()` ([panel.py:3304](../../../panel.py))

**Interfaces:**
- Produces: константы `LIGHT`, `DARK`, `TOKENS` перед `CSS`; переменные `--bg --panel --line --fill --fg --dim --dim2 --blue --green --red --orange --down --up --mut --track --r-panel --r-ctl --r-pill --s1…--s6 --sh --f-h1 --f-group --f-row --f-sec --f-hero`; классы `.panel .list .row .btn .btn.tinted .btn.bad .field .sw .seg .sheet .pop`. Всё дальнейшее строится на них.

Спека называла четыре набора значений; здесь их три, и это упрощение, а не отступление: ручная светлая тема выигрывает у media-запроса за счёт `:not([data-theme=light])` на самом media-блоке, поэтому четвёртый набор не нужен и значения светлой темы не дублируются.

- [ ] **Step 1: Написать провал — селфтест ловит цветовой литерал**

Дописать в `selftest()` перед блоком `ru = set(STRINGS["ru"])`:

```python
    # Цвет живёт в переменных, иначе одна из двух тем ломается молча. Литерал
    # ищется после двоеточия: так селектор вроде #chartbox не считается цветом.
    page_css = PAGE_T.split("<style>", 1)[1].split("</style>", 1)[0]
    for name, css in (("CSS", CSS[len(TOKENS):]),
                      ("PAGE_T", page_css.replace("{{CSS}}", ""))):
        bad = re.search(r":[^;{}]*#[0-9a-fA-F]{3,8}\b", css)
        assert not bad, f"{name}: цвет мимо токенов — {bad.group(0)!r}"
    assert "prefers-color-scheme" in TOKENS, "тёмная тема потерялась"
```

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `NameError: name 'TOKENS' is not defined` — константы ещё нет.

- [ ] **Step 3: Написать токены**

Заменить нынешний блок `:root{…}` и `@media (prefers-color-scheme:light){…}` в начале `CSS` на константы **перед** `CSS`:

```python
# Светлая — значения по умолчанию: панель равняется на Настройки macOS, а те
# светлые. Тёмная описана один раз и подставляется в два селектора — в
# media-запрос для тех, кто ничего не выбирал, и в атрибут для ручного выбора.
LIGHT = """--bg:#F2F2F7;--panel:#FFFFFF;--line:rgba(60,60,67,.29);
  --fill:rgba(120,120,128,.12);--fg:#000000;--dim:rgba(60,60,67,.6);
  --dim2:rgba(60,60,67,.3);--blue:#007AFF;--green:#34C759;--red:#FF3B30;
  --orange:#FF9500;--mut:rgba(120,120,128,.35);--track:rgba(120,120,128,.16);
  --redbg:rgba(255,59,48,.12);--bluebg:rgba(0,122,255,.12);
  --sh:0 8px 30px rgba(0,0,0,.14)"""

DARK = """--bg:#1C1C1E;--panel:#2C2C2E;--line:rgba(84,84,88,.6);
  --fill:rgba(120,120,128,.24);--fg:#FFFFFF;--dim:rgba(235,235,245,.6);
  --dim2:rgba(235,235,245,.3);--blue:#0A84FF;--green:#30D158;--red:#FF453A;
  --orange:#FF9F0A;--mut:rgba(120,120,128,.45);--track:rgba(120,120,128,.24);
  --redbg:rgba(255,69,58,.18);--bluebg:rgba(10,132,255,.18);
  --sh:0 8px 30px rgba(0,0,0,.5)"""

# Форма и кегль от темы не зависят, поэтому объявлены один раз. --on здесь же:
# кнопка переключателя и текст на синей кнопке белые в обеих темах.
SHAPE = """--on:#FFFFFF;--r-panel:10px;--r-ctl:6px;--r-pill:999px;
  --s1:4px;--s2:8px;--s3:12px;--s4:16px;--s5:24px;--s6:32px;
  --f-h1:20px;--f-group:13px;--f-row:14px;--f-sec:12px;--f-hero:28px;
  --down:var(--blue);--up:var(--orange)"""

TOKENS = (" :root{%s;%s}\n"
          " @media (prefers-color-scheme:dark){:root:not([data-theme=light]){%s}}\n"
          " :root[data-theme=dark]{%s}\n" % (LIGHT, SHAPE, DARK, DARK))
```

- [ ] **Step 4: Написать примитивы**

`CSS` становится `TOKENS + """…"""`. Тело — базовые правила и примитивы:

```python
CSS = TOKENS + """
 *{box-sizing:border-box}
 body{font:var(--f-row)/1.45 system-ui,sans-serif;margin:0;
      padding:var(--s5) var(--s5) var(--s6);background:var(--bg);color:var(--fg);
      -webkit-font-smoothing:antialiased}
 h1{font-size:var(--f-h1);font-weight:600;margin:0;letter-spacing:-.01em}
 h2{font-size:var(--f-group);font-weight:600;margin:0;letter-spacing:0}
 .num{font-variant-numeric:tabular-nums;white-space:nowrap}
 .mono{font-family:ui-monospace,SFMono-Regular,monospace;
       font-variant-numeric:tabular-nums}
 .dim{color:var(--dim)}
 .sec{font-size:var(--f-sec);color:var(--dim)}
 .hint{color:var(--dim);font-size:var(--f-sec);margin:var(--s2) 0 0;
       overflow-wrap:anywhere}

 /* Панель: белое на сером отделяется само, поэтому рамки нет. В тёмной теме
    серое на сером не отделяется — там она волосяная. */
 .panel{background:var(--panel);border-radius:var(--r-panel);
        padding:var(--s4);margin-bottom:var(--s4)}
 @media (prefers-color-scheme:dark){:root:not([data-theme=light]) .panel{
   box-shadow:0 0 0 .5px var(--line)}}
 :root[data-theme=dark] .panel{box-shadow:0 0 0 .5px var(--line)}

 /* Строка списка. Разделитель отступлен слева под контент — маковский приём:
    он показывает, где начинается смысл строки. */
 .list{display:flex;flex-direction:column}
 .row{display:flex;align-items:center;gap:var(--s3);min-height:44px;
      padding:var(--s2) 0;border-bottom:.5px solid var(--line)}
 .row:last-child{border-bottom:0}
 .list.inset .row{margin-left:var(--s6)}
 .list.inset .row>:first-child{margin-left:calc(-1 * var(--s6))}
 .row .sp{flex:1}

 button,select,input{font:inherit;color:inherit}
 .btn{background:none;border:0;border-radius:var(--r-ctl);cursor:pointer;
      padding:var(--s1) var(--s2);color:var(--blue)}
 .btn:hover{background:var(--fill)}
 .btn.plain{color:var(--fg)}
 .btn.bad{color:var(--red)}
 .btn:disabled{color:var(--dim2);cursor:default;background:none}
 .btn.tinted{background:var(--blue);color:#FFF}
 .field{background:var(--fill);border:0;border-radius:var(--r-ctl);
        padding:var(--s1) var(--s2);min-width:0}
 .field:focus,.btn:focus-visible,.sw:focus-visible,.seg button:focus-visible{
   outline:2px solid var(--blue);outline-offset:1px}

 /* Переключатель — сам чекбокс без нативного вида, кнопка это его ::before. */
 .sw{appearance:none;-webkit-appearance:none;flex:none;position:relative;
     width:38px;height:22px;padding:0;margin:0;border-radius:var(--r-pill);
     background:var(--track);cursor:pointer;transition:background .15s}
 .sw::before{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;
     border-radius:50%;background:#FFF;box-shadow:0 1px 3px rgba(0,0,0,.3);
     transition:transform .15s}
 .sw:checked{background:var(--green)}
 .sw:checked::before{transform:translateX(16px)}

 .seg{display:inline-flex;background:var(--track);border-radius:var(--r-pill);
      padding:2px}
 .seg button{background:none;border:0;border-radius:var(--r-pill);cursor:pointer;
      padding:var(--s1) var(--s3);font-size:var(--f-sec);color:var(--dim)}
 .seg button.on{background:var(--panel);color:var(--fg);
      box-shadow:0 1px 3px rgba(0,0,0,.18)}

 .sheet{position:fixed;inset:0;z-index:20;background:rgba(0,0,0,.35);
        display:flex;align-items:center;justify-content:center;padding:var(--s4)}
 .sheet>div{background:var(--panel);border-radius:14px;box-shadow:var(--sh);
        width:min(30rem,100%);max-height:86vh;overflow:auto;padding:var(--s5)}

 .pop{position:absolute;z-index:9;padding:var(--s2) var(--s3);
      background:var(--panel);border-radius:var(--r-ctl);box-shadow:var(--sh);
      font-size:var(--f-sec);pointer-events:none;white-space:nowrap}
 a{color:var(--blue)}
 @media (max-width:620px){body{padding:var(--s3) var(--s3) var(--s5)}
  .panel{padding:var(--s3)}}
"""
```

Два `#FFF` в коде выше — у `.sw::before` и `.btn.tinted` — надо заменить на `var(--on)`: они белые в обеих темах, но литерал есть литерал, и селфтест из шага 1 на них сработает.

- [ ] **Step 5: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`. Если ругается на литерал — искать в теле `CSS` или в `<style>` внутри `PAGE_T` оставшийся hex.

- [ ] **Step 6: Посмотреть глазами**

Открыть стенд. Страница будет выглядеть **сломанной**: старая разметка использует классы `.card`, `.srow`, `.act`, которых больше нет. Это ожидаемо — на этом шаге проверяется только, что фон, текст и переключатели в настройках взяли новые цвета и что светлая тема включается сменой системной темы.

- [ ] **Step 7: Коммит**

```bash
git add panel.py
git commit -m "Дизайн: токены и примитивы вместо переменных цвета"
```

---

### Task 3: Тема с ручным выбором

**Files:**
- Modify: `panel.py` — `HEAD` ([panel.py:2189](../../../panel.py)), `STRINGS`, `PAGE_T` (шит настроек появится в задаче 5; пока селект кладётся в нынешний `.gear`), `selftest()`

**Interfaces:**
- Produces: `localStorage.gwacl_theme` ∈ {отсутствует, `light`, `dark`}; `document.documentElement.dataset.theme`; id `s_theme`; ключи `theme`, `themeAuto`, `themeLight`, `themeDark` в обеих таблицах `STRINGS`; JS-функция `setTheme(v)`.

- [ ] **Step 1: Написать провал**

В `selftest()`, рядом с проверкой литералов:

```python
    assert "gwacl_theme" in HEAD, "тема будет мигать: нет скрипта в HEAD"
    assert "[data-theme=dark]" in TOKENS, "ручной выбор тёмной не переопределяет"
```

и добавить `s_theme` в кортеж проверяемых id.

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `AssertionError: тема будет мигать: нет скрипта в HEAD`.

- [ ] **Step 3: Скрипт против мигания**

В конец `HEAD` (он общий для страницы и логина, поэтому тема применяется и там):

```html
<script>/* до первой отрисовки, иначе тёмная панель моргнёт светлой */
try{var t=localStorage.gwacl_theme;
if(t=="dark"||t=="light")document.documentElement.dataset.theme=t}catch(e){}</script>
```

- [ ] **Step 4: Строки**

В `STRINGS["ru"]`: `"theme": "Тема"`, `"themeAuto": "Авто"`, `"themeLight": "Светлая"`, `"themeDark": "Тёмная"`. В `STRINGS["en"]`: `"theme": "Theme"`, `"themeAuto": "Auto"`, `"themeLight": "Light"`, `"themeDark": "Dark"`.

- [ ] **Step 5: Контрол и обработчик**

В настройки (пока в нынешний `.gear`, в задаче 5 переедет в шит):

```html
<label>{{t.theme}}<select id=s_theme onchange="setTheme(this.value)">
 <option value=auto>{{t.themeAuto}}<option value=light>{{t.themeLight}}
 <option value=dark>{{t.themeDark}}</select></label>
```

В `<script>`, рядом с `keep()`:

```js
// Тема — вкус того, кто смотрит, а не настройка шлюза: в config.json её нет,
// значит и saveCfg() о ней не знает.
const setTheme = v => {
  const r = document.documentElement;
  if (v === 'auto') { delete r.dataset.theme; } else { r.dataset.theme = v; }
  try { v === 'auto' ? localStorage.removeItem('gwacl_theme')
                     : localStorage.setItem('gwacl_theme', v); } catch (e) {}
};
try { s_theme.value = localStorage.gwacl_theme || 'auto'; } catch (e) {}
```

- [ ] **Step 6: Обновить `theme-color`**

Две меты в `HEAD` держат цвет браузерной обвязки и переменную читать не умеют —
это единственное разрешённое место с литералом. Значения должны совпасть с
новыми фонами:

```html
<meta name=theme-color content="#1C1C1E" media="(prefers-color-scheme: dark)">
<meta name=theme-color content="#F2F2F7" media="(prefers-color-scheme: light)">
```

При ручном выборе темы они разойдутся с панелью — это известная и принятая
цена, записанная в спеке.

- [ ] **Step 7: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 8: Проверить руками**

На стенде: переключить на «Светлая» — панель светлеет сразу; перезагрузить страницу — остаётся светлой и **не мигает** тёмным; вернуть «Авто» — панель идёт за системной темой. Проверить в приватном окне: там `localStorage` может бросать, панель обязана открыться в системной теме и не сломаться.

- [ ] **Step 9: Коммит**

```bash
git add panel.py
git commit -m "Тема: авто, светлая, тёмная — выбор переживает перезагрузку"
```

---

### Task 4: Шапка и слот баннеров

**Files:**
- Modify: `panel.py` — `PAGE_T` (разметка `.bar`, карточка `#upd`, `bypbox`, `off`), JS `draw()` и `stale()`, `STRINGS`, `selftest()`

**Interfaces:**
- Produces: `<header>` с id `hdr`; `<div id=banners>`; JS `banner(kind, text, act)`; ключ `close`. Удаляются id `msel`, `off`, `upd`, `updtext`. **`bypbox` остаётся** — `draw()` пишет в него, и элемент, убранный раньше своего кода, обрушит всю отрисовку. В шит его переносит задача 5.
- Consumes: примитивы `.btn`, `.panel` из задачи 2.

- [ ] **Step 1: Написать провал**

В кортеже id в `selftest()` заменить `"msel"`, `"off"`, `"upd"`, `"updtext"` на `"banners"`. `"bypbox"` не трогать.

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `AssertionError: the page has no banners`.

- [ ] **Step 3: Строки**

`STRINGS["ru"]`: `"close": "Закрыть"`. `STRINGS["en"]`: `"close": "Close"`.

- [ ] **Step 4: Разметка**

Заменить нынешний `<div class=bar>…</div>` и карточку `#upd` на:

```html
<header id=hdr>
 <h1>{{t.h1}}</h1><span class=sp></span>
 <span id=bypbox></span>
 <details class=gear>…нынешний блок настроек переносится сюда целиком, без
  единой правки…</details>
 <button class="btn plain" onclick="location='/logout'">{{t.logout}}</button>
</header>
<div id=banners></div>
```

Настройки на этом шаге остаются нынешним `<details class=gear>` и просто
переезжают в новую шапку: заменить их шитом здесь — значит оставить кнопку,
которая зовёт ещё не написанный `openSheet()`, и сломать панель на один коммит.
Шит — следующая задача, она же и удалит `.gear`.

CSS в `<style>` страницы:

```css
 #hdr{display:flex;align-items:center;gap:var(--s2);position:sticky;top:0;
      z-index:10;background:var(--bg);padding:var(--s3) 0;margin-bottom:var(--s3)}
 #hdr.stuck{box-shadow:0 .5px 0 var(--line)}
 #hdr .sp{flex:1}
 .ban{display:flex;align-items:center;gap:var(--s3);border-radius:var(--r-panel);
      padding:var(--s2) var(--s3);margin-bottom:var(--s2);font-size:var(--f-row)}
 .ban .sp{flex:1}
 .ban.red{background:var(--redbg);color:var(--red)}
 .ban.blue{background:var(--bluebg)}
 .ban.grey{background:var(--fill);color:var(--dim)}
```

- [ ] **Step 5: Рендер баннеров**

В `<script>`, рядом с `left()`:

```js
const banner = (kind, text, act) =>
  `<div class="ban ${kind}"><span class=sp>${text}</span>${act || ''}</div>`;
```

В `draw()` вместо кусков про `bypbox`, `upd`, `updtext`:

```js
  // esc: версия приходит из ответа GitHub. Сервер проверяет тег регуляркой
  // только там, где строит адрес загрузки, — на странице она чужой текст.
  banners.innerHTML =
      (S.bypass > S.now
        ? banner('red', `${T.bypOn} ${left(S.bypass - S.now)}`,
                 `<button class="btn bad" onclick="bypass(0)">${T.close}</button>`)
        : '')
    + (S.update
        ? banner('blue', esc(T.updateNew.replace('{v}', S.update)),
                 `<a class=btn href="{{RELEASES}}" target=_blank `
                 + `rel="noopener noreferrer">${T.updateWhat}</a>`
                 + `<button class=btn onclick=doUpdate()>${T.updateNow}</button>`)
        : '')
    + offban;
  if (S.update) announce(S.update);
```

`stale()` больше не пишет в `#off`, а держит строку баннера:

```js
let okAt = null, offban = '';
const stale = bad => {
  offban = bad ? banner('grey', T.offline.replace('{t}', okAt
    ? okAt.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '—')) : '';
  if (bad && S) draw();       // связь пропала — перерисовать нечем, кроме себя
  if (!bad) okAt = new Date();
};
```

Липкость шапки:

```js
onscroll = () => hdr.classList.toggle('stuck', scrollY > 4);
```

- [ ] **Step 6: Убрать мёртвое**

Из `PAGE_T` уходят: `<select id=msel>`, `<span id=off>`, кнопка CSV из шапки (переедет в задаче 6), карточка `#upd` целиком. Из JS — строки `msel.innerHTML = …` и `upd.hidden = …`. `bypass()` и кусок `draw()`, наполняющий `bypbox`, остаются нетронутыми: селект переезжает в шит задачей 5. Кнопка-предупреждение при открытом байпасе из `bypbox` уходит уже здесь — её роль забрал красный баннер.

- [ ] **Step 7: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 8: Проверить руками**

На стенде поставить в `STATE` `"update": "1.5.0"` и `"bypass": NOW + 700` — должны появиться синий и красный баннеры, шапка при прокрутке обрастает волосяной линией. Вернуть значения обратно. Остановить стенд (`Ctrl-C`) при открытой странице — через пять секунд появляется серый баннер с временем последнего ответа.

- [ ] **Step 9: Коммит**

```bash
git add panel.py
git commit -m "Шапка и баннеры: открытый шлюз и обновление больше не кнопки"
```

---

### Task 5: Шит настроек

**Files:**
- Modify: `panel.py` — `PAGE_T` (весь `<details class=gear>`), JS, `STRINGS`, `selftest()`

**Interfaces:**
- Produces: `<div class=sheet id=sheet hidden>`; JS `openSheet()`, `closeSheet()`; ключи `groupGeneral`, `groupNet`, `groupMaint`, `groupPw`. Все нынешние id полей (`s_lang`, `s_poll`, `s_keep`, `s_rb`, `s_reboot_at`, `s_port`, `s_iface`, `s_lan`, `s_self`, `s_pw`, `s_upd`, `s_ntf`, `s_check`, `s_reboot`, `s_theme`) сохраняются — `saveCfg()` не переписывается.

- [ ] **Step 1: Написать провал**

Добавить `"sheet"` в кортеж id в `selftest()`.

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `AssertionError: the page has no sheet`.

- [ ] **Step 3: Строки**

`ru`: `"groupGeneral": "Основное"`, `"groupNet": "Сеть"`, `"groupMaint": "Обслуживание"`, `"groupPw": "Пароль"`.
`en`: `"General"`, `"Network"`, `"Maintenance"`, `"Password"`.

- [ ] **Step 4: Разметка шита**

Вместо `<details class=gear>…</details>`:

```html
<div class=sheet id=sheet hidden onclick="if(event.target===this)closeSheet()">
 <div>
  <div class=shead><h1>{{t.settingsTitle}}</h1><span class=sp></span>
   <button class=btn onclick=closeSheet()>{{t.close}}</button></div>

  <h2 class=grp>{{t.groupGeneral}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sLang}}</span><select id=s_lang class=field>
    <option value=ru{{SEL_RU}}>Русский<option value=en{{SEL_EN}}>English</select></div>
   <div class=row><span class=sp>{{t.theme}}</span><select id=s_theme class=field
     onchange="setTheme(this.value)"><option value=auto>{{t.themeAuto}}
     <option value=light>{{t.themeLight}}<option value=dark>{{t.themeDark}}</select></div>
   <div class=row><span class=sp>{{t.sPoll}}</span>
    <input id=s_poll class=field type=number min=5 max=3600 value="{{POLL}}"></div>
   <div class=row><span class=sp>{{t.sKeep}}</span>
    <input id=s_keep class=field type=number min=1 max=24 value="{{KEEP}}"></div>
   <p class=hint>{{t.sKeepWhat}}</p>
  </div>

  <h2 class=grp>{{t.groupNet}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sPort}}</span>
    <input id=s_port class=field type=number min=1 max=65535 value="{{PORT}}"></div>
   <div class=row><span class=sp>{{t.sIface}}</span>
    <input id=s_iface class=field value="{{IFACE}}"></div>
   <div class=row><span class=sp>{{t.sLan}}</span>
    <input id=s_lan class=field value="{{LANCIDR}}"></div>
   <div class=row><span class=sp>{{t.sSelfIp}}</span>
    <input id=s_self class=field value="{{GW}}"></div>
   <p class=hint>{{t.sNetHint}}</p>
  </div>

  <h2 class=grp>{{t.groupMaint}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sRebootAt}}</span>
    <input id=s_reboot_at class=field type=time lang=en-GB value="{{REBOOT_AT}}"{{RB_OFF}}>
    <input id=s_rb class=sw type=checkbox{{RB}}
      onchange="s_reboot_at.disabled=!this.checked"></div>
   <div class=row><span class=sp>{{t.sUpdate}}</span><input id=s_upd class=sw
     type=checkbox{{UPD}} onchange="s_ntf.disabled=!this.checked"></div>
   <div class=row><span class=sp>{{t.sNotify}}</span><input id=s_ntf class=sw
     type=checkbox{{NTF}}{{NTF_OFF}} onchange=askNotify()></div>
   <p class=hint>{{t.sNotifyHint}}</p>
   <div class=row><span class=sp>{{t.byp}}</span><span id=bypbox></span></div>
   <div class=row><span class=sp></span>
    <button class=btn id=s_check onclick=checkUpd()>{{t.sCheck}}</button>
    <button class="btn bad" id=s_reboot onclick=rebootHost()>{{t.sReboot}}</button></div>
   <p class=hint>{{t.sCheckHint}}</p>
  </div>

  <h2 class=grp>{{t.groupPw}}</h2>
  <div class="list inset panel">
   <div class=row><span class=sp>{{t.sPw}}</span><input id=s_pw class=field
     type=password autocomplete=new-password placeholder="{{t.sPwKeep}}"></div>
  </div>

  <div class=srow2><span class="sec mono sp">gateway-acl {{VERSION}}</span>
   <button class="btn tinted" onclick=saveCfg()>{{t.sSave}}</button></div>
 </div>
</div>
```

CSS страницы:

```css
 .shead{display:flex;align-items:center;gap:var(--s2);margin-bottom:var(--s4)}
 .shead .sp{flex:1}
 .grp{margin:var(--s4) 0 var(--s2);color:var(--dim)}
 .srow2{display:flex;align-items:center;gap:var(--s2);margin-top:var(--s4)}
 .srow2 .sp{flex:1}
 .sheet .field{max-width:11rem}
 .sheet input:disabled{opacity:1;color:var(--dim);-webkit-text-fill-color:var(--dim);
   cursor:not-allowed}
```

- [ ] **Step 5: Открытие и закрытие**

```js
// details закрывался сам; шит — нет, поэтому Esc и клик мимо пишутся руками.
const openSheet = () => { sheet.hidden = false; s_lang.focus(); };
const closeSheet = () => { sheet.hidden = true; };
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !sheet.hidden) closeSheet();
});
```

- [ ] **Step 6: Байпас переезжает в шит**

`bypbox` теперь живёт строкой в группе «Обслуживание». Кусок `draw()`, который его наполняет, остаётся прежним, но кнопка-предупреждение из него уходит (её роль забрал красный баннер) — при открытом байпасе строка показывает оставшееся время текстом:

```js
  bypbox.innerHTML = S.bypass > S.now
    ? `<span class="sec num">${left(S.bypass - S.now)}</span>`
    : `<select class=field title="${T.bypWhat}" onchange="bypass(this.value,this)">`
      + `<option value="">${T.byp}</option>`
      + BYP.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
      + `</select>`;
```

- [ ] **Step 7: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 8: Проверить руками**

Открыть шит: группы строк, подпись слева, контрол справа, подсказки под своими группами. `Esc` и клик по затемнению закрывают. Выключить переключатель перезагрузки — поле времени гаснет, но остаётся читаемым. Нажать «Сохранить» — стенд отвечает пустой строкой, страница перезагружается: значит, `saveCfg()` нашёл все свои id.

- [ ] **Step 9: Коммит**

```bash
git add panel.py
git commit -m "Настройки: шит со сгруппированными строками вместо поповера"
```

---

### Task 6: Карточка трафика — заголовок и сводка

**Files:**
- Modify: `panel.py` — `PAGE_T` (карточка трафика), JS `draw()`, `selftest()`

**Interfaces:**
- Produces: id `mtitle` (заголовок «Август 2026 · Ноутбук ×»), `ksum` (вторая строка сводки); сохраняются `kt`, `kdelta`, `chartbox`, `mstrip`. Удаляются `kd`, `ku`, `ka`, `kother`, `kotherbox`, `othlbl`, `cumlbl`, `chsel`, `bday`, `bhour` (последние два заменяет сегментный контрол с id `seg`).

- [ ] **Step 1: Написать провал**

В кортеже id: убрать `kd`, `ku`, `ka`, `kother`, `kotherbox`, `othlbl`, `cumlbl`, `chsel`, `bday`, `bhour`; добавить `mtitle`, `ksum`, `seg`.

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `AssertionError: the page has no mtitle`.

- [ ] **Step 3: Разметка**

```html
<div class=row2>
 <div class=panel>
  <div class=chead><h2 id=mtitle></h2><span class=sp></span>
   <div class=seg id=seg>
    <button onclick="setMode('day')">{{t.byDay}}</button>
    <button onclick="setMode('hour')">{{t.byHour}}</button></div>
   <button class=btn onclick=csv() title="{{t.csvWhat}}">CSV</button>
  </div>
  <div class=hero><b class="num" id=kt></b><em id=kdelta></em></div>
  <div class="sec num" id=ksum></div>
  <div id=chartbox></div>
  <h3 class=grp>{{t.byMonth}}</h3>
  <div id=mstrip></div>
 </div>
 <div class=panel>
  <h2>{{t.sysTitle}}</h2>
  <div class="list inset" id=sysbox></div>
 </div>
</div>
```

CSS:

```css
 .row2{display:grid;gap:var(--s4);grid-template-columns:minmax(0,2fr) minmax(0,22rem);
       align-items:start}
 @media (max-width:900px){.row2{grid-template-columns:1fr}}
 .chead{display:flex;align-items:center;gap:var(--s2);margin-bottom:var(--s3)}
 .chead .sp{flex:1}
 .hero{display:flex;align-items:baseline;gap:var(--s2)}
 .hero b{font-size:var(--f-hero);font-weight:600;letter-spacing:-.02em}
 .hero em{font-style:normal;font-size:var(--f-sec);color:var(--dim)}
 #chartbox{position:relative;margin-top:var(--s4)}
 #chartbox svg{display:block;width:100%;height:auto}
```

- [ ] **Step 4: Заголовок и сводка в `draw()`**

Заменить блок, который наполнял `kt/kd/ku/ka/kother/kdelta/chsel`:

```js
  // Имя месяца берёт браузер: 12 названий на язык в STRINGS не нужны, а язык
  // панели он уже знает.
  const [my, mm] = S.month.split('-');
  const mname = new Date(+my, +mm - 1).toLocaleDateString(T.locale,
                  {month: 'long', year: 'numeric'});
  mtitle.innerHTML = mname[0].toUpperCase() + mname.slice(1)
    + (one ? ` · <button class=btn onclick="pickDev(null)" title="${T.showAll}">`
             + `${esc(one.name || one.ip)} ×</button>` : '');

  kt.textContent = fmt(U + D + oth);
  const pc = (!one && S.prev) ? Math.round((U + D + oth - S.prev) / S.prev * 100) : null;
  kdelta.textContent = pc === null ? '' : (pc > 0 ? '+' : '') + pc + '%';
  kdelta.title = pc === null ? '' : T.vsPrev;
  ksum.innerHTML = `↓ ${fmt(D)} · ↑ ${fmt(U)} · `
    + `${fmt(Math.round((U + D + oth) / Math.max(S.days.length, 1)))} ${T.perDay}`
    + (oth ? ` · ${T.other} ${fmt(oth)}${q(T.otherWhat)}` : '');

  for (const [i, b] of [...seg.children].entries())
    b.className = (i === 0) === (mode === 'day') ? 'on' : '';
```

Ключ `locale` — новый: `ru` → `"ru-RU"`, `en` → `"en-GB"`. Добавить в обе таблицы `STRINGS`.

- [ ] **Step 5: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 6: Проверить руками**

На стенде: заголовок «Август 2026», под ним крупное число с дельтой, ниже одна серая строка со стрелками и «прочее» с ⓘ. Сегментный контрол переключает день/сутки. Английская панель (`GWACL_DIR` с `{"lang":"en"}`) показывает «August 2026». Кликнуть по устройству в таблице — заголовок становится «Август 2026 · Ноутбук ×», «прочее» пропадает.

- [ ] **Step 7: Коммит**

```bash
git add panel.py
git commit -m "Трафик: месяц в заголовке, сводка двумя строками вместо пяти плиток"
```

---

### Task 7: График в стиле Аккумулятора

**Files:**
- Modify: `panel.py` — JS `chart()`, новая `hover()`, CSS страницы

**Interfaces:**
- Consumes: `rows()` — без изменений, тот же формат `[короткая метка, up, down, полная метка, other]`.
- Produces: `chart(rs, cum)` рисует SVG со скруглёнными столбцами и без сетки; `hover(i)` показывает `.pop`. Легенда и `#cumlbl` удаляются из разметки.

- [ ] **Step 1: Переписать `chart()`**

```js
const chart = (rs, cum) => {
  if (!rs.length) return `<p class=hint>${mode === 'hour' ? T.noHours
    : mtot ? T.rolled : T.noData}</p>`;
  const W = Math.max(chartbox.clientWidth || 720, 280), H = 180, B = 18, top = 16;
  const max = Math.max(...rs.map(d => d[1] + d[2] + d[4]), 1024);
  const bw = W / rs.length, plot = H - B - top;
  const y = v => top + plot - (v / max) * plot;
  // Единственная линия: потолок. Ось слева не нужна — цифры даёт карточка.
  let g = `<line x1=0 x2=${W} y1=${y(max)} y2=${y(max)} stroke="var(--line)"/>`
    + `<text x=0 y=${y(max) - 5} fill="var(--dim)" font-size=10>${fmtAx(max)}</text>`;
  const bars = rs.map((d, i) => {
    const x = i * bw + bw * .18, w = Math.max(1, bw * .64), o = d[4];
    const r = Math.min(2, w / 2);
    const lbl = rs.length > 20 ? (i % 5 === 0) : true;
    // Скругление только сверху: rect с rx скруглил бы и основание, поэтому
    // верхний сегмент рисуется путём, а нижние — обычными прямоугольниками.
    const cap = (yy, hh, fill) => hh < .5 ? '' :
      `<path d="M${x} ${yy + hh}V${yy + r}q0 -${r} ${r} -${r}h${w - 2 * r}`
      + `q${r} 0 ${r} ${r}V${yy + hh}z" fill="${fill}"/>`;
    const box = (yy, hh, fill) => hh < .5 ? '' :
      `<rect x=${x} y=${yy} width=${w} height=${hh} fill="${fill}"/>`;
    const hu = (d[1] / max) * plot, hd = (d[2] / max) * plot, ho = (o / max) * plot;
    return `<g data-i=${i} onmouseenter="hover(${i})" onmouseleave="hover(-1)">`
      + `<title>${d[3]}  ↓ ${fmt(d[2])}  ↑ ${fmt(d[1])}`
      + `${o ? `  ${T.other} ${fmt(o)}` : ''}</title>`
      + (o ? cap(y(d[1] + d[2] + o), ho, 'var(--mut)')
           : cap(y(d[1] + d[2]), hu, 'var(--up)'))
      + (o ? box(y(d[1] + d[2]), hu, 'var(--up)') : '')
      + box(y(d[2]), hd, 'var(--down)')
      + `<rect x=${i * bw} y=${top} width=${bw} height=${plot} fill="none" `
      + `pointer-events="all"/></g>`
      + (lbl ? `<text x=${x + w / 2} y=${H - 4} text-anchor=middle `
             + `fill="var(--dim)" font-size=10>${d[0]}</text>` : '');
  }).join('');
  let line = '';
  const tot = rs.reduce((a, d) => a + d[1] + d[2] + d[4], 0);
  if (cum && rs.length > 1 && tot) {
    let run = 0;
    const pts = rs.map((d, i) => { run += d[1] + d[2] + d[4];
      return `${(i * bw + bw / 2).toFixed(1)},${(top + plot - run / tot * plot).toFixed(1)}`;
    }).join(' ');
    line = `<polyline fill=none stroke="var(--dim2)" stroke-width=1 `
      + `stroke-dasharray="2 3" points="${pts}"><title>${T.cumul}  `
      + `${fmt(tot)}</title></polyline>`;
  }
  return `<svg viewBox="0 0 ${W} ${H}">${g}${bars}${line}</svg>`
    + `<div class=pop hidden></div>`;
};
```

- [ ] **Step 2: Карточка при наведении**

```js
// Наведение не перерисовывает график: столбцы гасятся классом, карточка —
// один div, который переезжает. Иначе каждое движение мыши стоило бы SVG.
const hover = i => {
  const svg = chartbox.querySelector('svg'), pop = chartbox.querySelector('.pop');
  if (!svg || !pop) return;
  svg.classList.toggle('dim', i >= 0);
  for (const g of svg.querySelectorAll('g')) g.classList.toggle('hi', +g.dataset.i === i);
  if (i < 0) { pop.hidden = true; return; }
  const d = rows()[i];
  pop.innerHTML = `<b>${d[3]}</b><br>`
    + `<span style="color:var(--down)">↓</span> ${fmt(d[2])} · `
    + `<span style="color:var(--up)">↑</span> ${fmt(d[1])}`
    + (d[4] ? ` · ${T.other} ${fmt(d[4])}` : '');
  pop.hidden = false;
  const box = svg.getBoundingClientRect(), bw = box.width / rows().length;
  const x = (i + .5) * bw - pop.offsetWidth / 2;
  pop.style.left = Math.max(0, Math.min(box.width - pop.offsetWidth, x)) + 'px';
  pop.style.top = '0px';
};
```

CSS:

```css
 svg.dim g{opacity:.4}
 svg.dim g.hi{opacity:1}
```

- [ ] **Step 3: Убедиться, что легенды не осталось**

Разметку легенды снесла задача 6 вместе со всей карточкой трафика. Здесь надо
добить хвосты: правила `.legend` в CSS страницы и строку `cumlbl.hidden = mode
!== 'day'` в `draw()`, если она пережила. Ключи `inbound`, `outbound`, `other`,
`cumul` остаются — их использует сводка, карточка наведения и `<title>` пунктира.

- [ ] **Step 4: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 5: Проверить руками**

Столбцы скруглены сверху и не «съезжают» основанием. Наведение: карточка над столбцом, остальные гаснут, увод мыши — всё возвращается. Переключить на «за сутки» — карточка работает и там. Проверить с клавиатуры: `Tab` до графика значений не даёт, но нативный `<title>` остаётся — навести и подождать, всплывёт системная подсказка.

- [ ] **Step 6: Коммит**

```bash
git add panel.py
git commit -m "График: скруглённые столбцы, карточка вместо легенды и сетки"
```

---

### Task 8: Полоса месяцев с годом

**Files:**
- Modify: `panel.py` — JS `strip()`, CSS страницы

**Interfaces:**
- Produces: `strip()` рисует те же 12 столбиков, но подпись двухэтажная: месяц, а под ним год — у первого столбика и у каждого января.

- [ ] **Step 1: Переписать `strip()`**

```js
const strip = () => {
  const ms = S.months.slice(-12), max = Math.max(...ms.map(m => m[1]), 1);
  return `<div class=months>` + ms.map((m, i) => {
    const [yy, mm] = m[0].split('-');
    // Год только там, где он меняется: двенадцать одинаковых подписей ничего
    // не сообщают, а «12» слева и «08» справа — это разные годы.
    const yr = (i === 0 || mm === '01') ? `<u>${yy.slice(2)}</u>` : '';
    return `<button class="mo${m[0] === S.month ? ' cur' : ''}" `
      + `onclick="load('${m[0]}')" title="${m[0]}  ${fmt(m[1])}">`
      + `<i style="height:${Math.max(2, m[1] / max * 46).toFixed(0)}px"></i>`
      + `<span>${mm}</span>${yr}</button>`;
  }).join('') + `</div>`;
};
```

- [ ] **Step 2: CSS**

```css
 .months{display:flex;gap:var(--s1);align-items:flex-end}
 .mo{flex:1;min-width:0;background:none;border:0;padding:var(--s1) 0;cursor:pointer;
     display:flex;flex-direction:column;justify-content:flex-end;align-items:center;
     gap:var(--s1)}
 .mo i{display:block;width:100%;max-width:1.4rem;background:var(--mut);
       border-radius:3px 3px 0 0}
 .mo:hover i{background:var(--dim2)}
 .mo.cur i{background:var(--blue)}
 .mo span{font-size:var(--f-sec);color:var(--dim);font-variant-numeric:tabular-nums}
 .mo u{font-size:10px;color:var(--dim2);text-decoration:none}
 .mo.cur span{color:var(--fg);font-weight:600}
```

- [ ] **Step 3: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 4: Проверить руками**

На стенде `S.months` охватывает два года: под первым столбиком и под январём стоит год, выбранный месяц синий и жирный, клик по столбику меняет месяц и заголовок карточки.

- [ ] **Step 5: Коммит**

```bash
git add panel.py
git commit -m "Полоса месяцев: год там, где он меняется"
```

---

### Task 9: Машина

**Files:**
- Modify: `panel.py` — JS `machine()`, `srow()`, `meter()`, `q()`, CSS страницы

**Interfaces:**
- Produces: `machine(s)` возвращает список `.row`; метр остаётся у процессора, памяти, подкачки и диска; у нагрузки и температуры — только значение и ⓘ.

- [ ] **Step 1: Переписать строки**

```js
// ⓘ, а не кружок с вопросом: тот же CSS-механизм — нативный title не годится,
// карточка перерисовывается на каждом опросе и снимает незакрытую подсказку.
const q = text => `<i class=q tabindex=0>ⓘ<span>${esc(text)}</span></i>`;
const meter = (pct, warn) => `<div class=meter><i style="width:`
  + `${Math.min(100, Math.max(0, pct)).toFixed(0)}%`
  + `${pct >= warn ? ';background:var(--red)' : ''}"></i></div>`;
const srow = (label, val, pct, warn) =>
  `<div class=row><span class=sp>${label}</span><b class=num>${val}</b></div>`
  + (pct === null ? '' : meter(pct, warn));
```

- [ ] **Step 2: Убрать метры там, где нет потолка**

В `machine()` заменить две строки:

```js
  if (s.load) h += srow(T.sLoad, s.load.map(x => x.toFixed(2)).join('  ')
      + (s.cores ? '  · ' + n(T.cores, s.cores) : ''), null);
  if (s.temp) h += srow(T.sTemp + q(n(T.tempWhat, s.temp[1])),
                        s.temp[0].toFixed(0) + ' °C', null);
```

Остальные вызовы `srow` не трогаются: у процессора, памяти, подкачки и диска потолок настоящий.

- [ ] **Step 3: CSS**

```css
 .meter{height:3px;border-radius:var(--r-pill);background:var(--track);
        margin:0 0 var(--s2) var(--s6)}
 .meter i{display:block;height:100%;border-radius:var(--r-pill);background:var(--blue)}
 .q{position:relative;margin-left:var(--s1);color:var(--dim);font-style:normal;
    font-size:var(--f-sec);cursor:help}
 .q:hover,.q:focus{color:var(--fg);outline:none}
 .q>span{display:none;position:absolute;z-index:9;left:0;top:calc(100% + var(--s1));
    width:min(15rem,62vw);padding:var(--s2) var(--s3);background:var(--panel);
    border-radius:var(--r-ctl);box-shadow:var(--sh);color:var(--fg);
    font-size:var(--f-sec);line-height:1.4;white-space:normal}
 .q:hover>span,.q:focus>span{display:block}
```

- [ ] **Step 4: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 5: Проверить руками**

Карточка машины — список с разделителями, метры под четырьмя строками из восьми, ⓘ у температуры открывается по наведению и по `Tab`+фокусу. Задержать курсор внутри карточки на десять секунд: содержимое не должно моргать (в `draw()` уже есть проверка `sysbox.matches(':hover')`).

- [ ] **Step 6: Коммит**

```bash
git add panel.py
git commit -m "Машина: список строк, метр только там, где есть потолок"
```

---

### Task 10: Строка устройства с раскрытием

**Files:**
- Modify: `panel.py` — `PAGE_T` (таблица устройств), JS `draw()`, `spark()`, CSS страницы, `selftest()`

**Interfaces:**
- Produces: `<div class=list id=tb>` вместо `<table>`; переменная `openIp` — адрес раскрытой строки; `toggleRow(ip)`; `devRow(x, …)` и `devDetail(x, …)`. Удаляются id `h_ip`, `h_name`, `h_traf`, `h_now`, `h_seen`.
- Consumes: `post()`, `setName()`, `del()`, `timer()`, `pickDev()`, `addKnown()` — без изменений.

Раскрытие живёт в переменной, а не в DOM: `draw()` перерисовывает список каждые пять секунд, и состояние, хранящееся только в разметке, схлопнулось бы само. Это главный риск задачи.

- [ ] **Step 1: Написать провал**

Из кортежа id убрать `h_ip`, `h_name`, `h_traf`, `h_now`, `h_seen`; `tb` остаётся.

- [ ] **Step 2: Убедиться, что селфтест ещё зелёный**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok` — id пока на месте, проверка просто перестала их требовать.

- [ ] **Step 3: Строки**

`ru`: `"showInChart": "Показать в графике"`. `en`: `"Show in chart"`.

- [ ] **Step 4: Разметка**

Заменить `<table>…</table>` на:

```html
<div class="list inset" id=tb></div>
```

Заголовок блока и форму добавления трогает задача 11.

- [ ] **Step 5: Рендер строки**

В `draw()` вместо `tb.innerHTML = list.map(x => …)`:

```js
  tb.innerHTML = list.map(x => {
    const t = x.up + x.down, me = x.ip === S.you, r = x.rate[0] + x.rate[1];
    const live = r > 0 || (x.seen && S.now - x.seen < fresh);
    const op = openIp === x.ip;
    return `<div class="drow${x.on ? '' : ' off'}${op ? ' open' : ''}">`
     + `<div class=dmain onclick="toggleRow('${esc(x.ip)}')">`
     + `<i class="dot${live ? ' live' : ''}" `
     + `title="${live ? T.dotLive : T.dotQuiet}"></i>`
     + `<div class=dname>`
     // stopPropagation: клик по имени правит имя, а не раскрывает строку.
     + `<input class=nm value="${esc(x.name)}" placeholder="${esc(x.host || T.phName)}" `
     + `onclick="event.stopPropagation()" `
     + `onchange="setName('${esc(x.ip)}',this.value)">`
     // Имя, которым устройство представляется сети, предложено как имя, которое
     // можно оставить. Через data-, не в onclick: hostname из чужого файла аренд.
     + (!x.name && x.host ? `<button class=ghost data-ip="${esc(x.ip)}" `
        + `data-nm="${esc(x.host)}" onclick="event.stopPropagation();addKnown(this)" `
        + `title="${esc(n(T.useHost, x.host))}">+</button>` : '')
     + `<div class=sec><span class=mono>${esc(x.ip)}</span>`
     + `${me ? ' · ' + T.youAre : ''} · ${x.seen ? ago(S.now - x.seen) : '—'}</div>`
     + `</div><span class=sp></span>`
     + `<div class=dnum><b class=num>${fmt(t)}</b>`
     + `<div class="sec num">${r > 0 ? `↓ ${fmt(x.rate[1])}${T.perSec}`
        + `  ↑ ${fmt(x.rate[0])}${T.perSec}` : '—'}</div></div>`
     + `<span class=chev>›</span>`
     + `<input class=sw type=checkbox${x.on ? ' checked' : ''} `
     + `onclick="event.stopPropagation()" `
     + `onchange="post({ip:'${esc(x.ip)}',on:this.checked})">`
     + `</div>${op ? devDetail(x, peak) : ''}</div>`;
  }).join('') || `<p class=hint>${fq ? T.noMatch : T.empty}</p>`;
```

- [ ] **Step 6: Рендер раскрытия**

Рядом с `spark()`:

```js
const devDetail = (x, peak) => `<div class=ddet>`
  + spark(x.series, peak, x.on)
  + `<div class=dacts>`
  + (x.until > S.now
      ? `<button class=btn title="${T.tmCancel}" `
        + `onclick="post({ip:'${esc(x.ip)}',for:0})">${left(x.until - S.now)} ×</button>`
      : `<select class=field title="${T.tmWhat}" `
        + `onchange="timer('${esc(x.ip)}',${!x.on},this)">`
        + `<option value="">${T.tmFor}</option>`
        + TIMES.map(([v, k]) => `<option value="${v}">${T[k]}</option>`).join('')
        + `</select>`)
  // vpnOff — это «мимо VPN»: у переключателя подпись называет состояние, в
  // которое он включён, а не действие, как называла его кнопка.
  + (S.vpnable ? `<label class=vpn title="${T.vpnWhat}">${T.vpnOff}`
      + `<input class=sw type=checkbox${x.vpn ? '' : ' checked'} `
      + `onchange="post({ip:'${esc(x.ip)}',vpn:!this.checked})"></label>` : '')
  + `<button class=btn onclick="pickDev('${esc(x.ip)}')">${T.showInChart}</button>`
  + `<span class=sp></span>`
  + `<button class="btn bad" onclick="del('${esc(x.ip)}',${x.ip === S.you})">`
  + `${T.del}</button></div>`
  + `<div class="sec mono">${esc(x.mac)}</div></div>`;

// Раскрытие держится в переменной, а не в разметке: draw() перерисовывает
// список каждые пять секунд и стёр бы состояние, живущее только в DOM.
// open — имя функции окна; своя переменная с тем же именем перекрыла бы её
// на весь скрипт, поэтому openIp.
let openIp = null;
const toggleRow = ip => { openIp = openIp === ip ? null : ip; draw(); };
```

Объявление `openIp` кладётся рядом с `let S = null, month = null, sel = null, …`, а не в конец файла: переменная нужна `draw()`.

- [ ] **Step 7: Спарклайн во всю ширину**

```js
const spark = (ser, max, on) => {
  if (!ser || ser.length < 2) return '';
  const w = 240, h = 28, bw = w / ser.length;
  return `<svg class=spark viewBox="0 0 ${w} ${h}" preserveAspectRatio=none `
    + `fill="var(--down)"${on ? '' : ' opacity=.35'}>`
    + ser.map((v, i) => { const t = (v[0] + v[1]) / max * h;
        return t < .4 ? '' : `<rect x="${(i * bw).toFixed(2)}" y="${(h - t).toFixed(2)}" `
          + `width="${Math.max(.7, bw * .72).toFixed(2)}" height="${t.toFixed(2)}"/>`;
      }).join('') + `</svg>`;
};
```

- [ ] **Step 8: CSS**

```css
 .drow{border-bottom:.5px solid var(--line)}
 .drow:last-child{border-bottom:0}
 .dmain{display:flex;align-items:center;gap:var(--s3);min-height:48px;
        padding:var(--s2) 0;cursor:pointer}
 .dmain .sp{flex:1}
 .dname{min-width:0;flex:0 1 14rem}
 .nm{background:none;border:0;border-radius:var(--r-ctl);padding:2px var(--s1);
     width:100%;font-size:var(--f-row)}
 .nm:hover{background:var(--fill)}
 .nm:focus{background:var(--fill);outline:2px solid var(--blue);outline-offset:0}
 .dnum{text-align:right}
 .dot{flex:none;width:7px;height:7px;border-radius:50%;background:transparent}
 .dot.live{background:var(--green)}
 .chev{color:var(--dim2);transition:transform .15s;display:inline-block}
 .drow.open .chev{transform:rotate(90deg)}
 .drow.off .nm,.drow.off .dnum{color:var(--dim)}
 .ddet{padding:0 0 var(--s3) var(--s5);display:flex;flex-direction:column;
       gap:var(--s2)}
 .spark{display:block;width:100%;height:28px}
 .dacts{display:flex;align-items:center;gap:var(--s2);flex-wrap:wrap}
 .dacts .sp{flex:1}
 .vpn{display:flex;align-items:center;gap:var(--s2);font-size:var(--f-sec);
      color:var(--dim)}
```

- [ ] **Step 9: Убрать мёртвое**

Удаляются: `<thead>` со всеми `th`, объект `HEADS`, цикл `for (const th of document.querySelectorAll('th.s'))`, правила CSS для `table`, `th`, `td`, `tr.pick`, `.act`, `.me`, `.off td`, и весь мобильный блок `@media (max-width:620px)` в части `thead{display:none}` и перекладывания ячеек.

Кнопка `+` (подставить имя из DHCP) **остаётся** — она в шаге 5 выше. Её правила
переписываются под новую строку:

```css
 .dname{position:relative}
 .ghost{position:absolute;right:2px;top:2px;padding:0 var(--s1);font-size:var(--f-sec);
        color:var(--dim);background:var(--fill);border:0;border-radius:var(--r-ctl);
        cursor:pointer}
 .ghost:hover{color:var(--fg)}
 @media (hover:hover){.ghost{opacity:0;transition:opacity .1s}
  .drow:hover .ghost,.ghost:focus{opacity:1}}
```

- [ ] **Step 10: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 11: Проверить руками — главная проверка плана**

1. Раскрыть строку. **Подождать 15 секунд** (три опроса). Строка обязана остаться раскрытой, спарклайн — перерисоваться.
2. Щёлкнуть переключатель — строка не раскрывается и не схлопывается, устройство меняет состояние.
3. Щёлкнуть по имени — строка не раскрывается, курсор встаёт в поле; набрать текст, подождать десять секунд: текст не должен пропасть (в `setInterval` уже есть проверка `activeElement`).
4. Раскрыть, открыть селект таймера, подождать — селект не закрывается.
5. Сузить окно до 380px — строка не ломается и не требует горизонтальной прокрутки.

- [ ] **Step 12: Коммит**

```bash
git add panel.py
git commit -m "Устройства: строка списка с переключателем и раскрытием"
```

---

### Task 11: Заголовок блока, сортировка, поиск, добавление

**Files:**
- Modify: `panel.py` — `PAGE_T` (шапка блока устройств и форма), JS `sortBy()`, `draw()`, `selftest()`

**Interfaces:**
- Produces: id `srt` (селект ключа), `srtd` (кнопка направления), `allsw`, `flt`, `lanips` — сохраняются; форма добавления заворачивается в `<details id=addrow>`. Ключи `sortBy`, `addDevice`.

- [ ] **Step 1: Написать провал**

Добавить `"srt"`, `"srtd"`, `"addrow"` в кортеж id в `selftest()`.

- [ ] **Step 2: Убедиться, что провал настоящий**

```bash
python3 panel.py --selftest
```

Ожидается `AssertionError: the page has no srt`.

- [ ] **Step 3: Строки**

`ru`: `"sortBy": "Сортировка"`, `"addDevice": "Добавить устройство"`.
`en`: `"Sort"`, `"Add device"`.

- [ ] **Step 4: Разметка**

```html
<div class=panel>
 <div class=chead><h2>{{t.devicesTitle}}</h2><span class=sp></span>
  <input id=flt class=field placeholder="{{t.filter}}" aria-label="{{t.filter}}"
    oninput=draw()>
  <select id=srt class=field title="{{t.sortBy}}" onchange=setSort(this.value)></select>
  <button class=btn id=srtd onclick=flipSort()></button>
  <button class=btn id=allsw onclick=toggleAll() title="{{t.allWhat}}"></button>
 </div>
 <div class="list inset" id=tb></div>
 <details id=addrow>
  <summary class=btn>+ {{t.addDevice}}</summary>
  <form id=f>
   <input name=ip class=field placeholder="{{EXAMPLE}}" list=lanips required>
   <datalist id=lanips></datalist>
   <input name=nm class=field placeholder="{{t.phName}}">
   <button class="btn tinted">{{t.add}}</button>
  </form>
 </details>
 <p class=hint>{{t.hint}}</p>
</div>
```

CSS:

```css
 #addrow>summary{list-style:none;display:inline-block;margin-top:var(--s3)}
 #addrow>summary::-webkit-details-marker{display:none}
 #addrow form{display:flex;gap:var(--s2);flex-wrap:wrap;margin-top:var(--s2)}
 #addrow form input{flex:1;min-width:8rem}
 #flt{max-width:9rem}
```

- [ ] **Step 5: Сортировка селектом**

Заменить `sortBy()`:

```js
// Ключ и направление разведены: раньше повторный клик по колонке переворачивал
// порядок, а у селекта повторный выбор того же пункта события не даёт.
const DIRDEF = {ip: 1, name: 1, traf: -1, now: -1, seen: -1};
const setSort = k => { sortk = k; sortd = DIRDEF[k]; keep(); draw(); };
const flipSort = () => { sortd = -sortd; keep(); draw(); };
```

В `draw()` вместо цикла по `HEADS`:

```js
  srt.innerHTML = Object.entries({ip: 'colAddr', name: 'colName', traf: 'colTraffic',
                                  now: 'colNow', seen: 'colSeen'})
    .map(([k, s]) => `<option value=${k}${k === sortk ? ' selected' : ''}>`
                     + `${T[s]}</option>`).join('');
  srtd.textContent = sortd > 0 ? '↑' : '↓';
  srtd.title = T.sortBy;
```

- [ ] **Step 6: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok`.

- [ ] **Step 7: Проверить руками**

Сортировка меняется селектом, стрелка переворачивает; перезагрузить страницу — выбор сохранился. `/` фокусирует поиск. «+ Добавить устройство» раскрывается, автодополнение из `S.lan` работает, после отправки форма очищается. «Выключить всех» спрашивает подтверждение и не трогает твоё устройство.

- [ ] **Step 8: Коммит**

```bash
git add panel.py
git commit -m "Устройства: сортировка селектом, добавление отдельной строкой"
```

---

### Task 12: Чужаки, конфликты, вход

**Files:**
- Modify: `panel.py` — `PAGE_T` (карточки `#clash`, `#unk`), JS `draw()`, `LOGIN_T`, CSS

**Interfaces:**
- Produces: `#clash`/`#clashb` и `#unk`/`#ub` рисуют `.list` из `.row`; `LOGIN_T` использует `.panel`, `.field`, `.btn.tinted`.

- [ ] **Step 1: Разметка карточек**

```html
<div class=panel id=clash hidden>
 <h2>{{t.clashTitle}}</h2>
 <div class="list inset" id=clashb></div>
</div>

<div class=panel id=unk hidden>
 <h2>{{t.blockedTitle}}</h2>
 <div class="list inset" id=ub></div>
 <p class=hint>{{t.blockedHint}}</p>
</div>
```

Абзац `<p class=hint>{{t.clashHint}}</p>` из карточки конфликтов уходит: то же объяснение теперь висит на ⓘ в строке, которую рисует следующий шаг.

- [ ] **Step 2: Рендер**

```js
  clash.hidden = !S.clash.length;
  clashb.innerHTML = S.clash.map(([ip, was, now, ven]) =>
    `<div class=row><div class=dname><b class=mono>${esc(ip)}</b>`
    + `<div class=sec>${esc(T.clashLine.replace('{a}', was).replace('{b}', now))}`
    + `${ven ? ' · ' + esc(ven) : ''}</div></div><span class=sp></span>`
    + `<span class=bad>${q(T.clashHint)}</span></div>`).join('');

  unk.hidden = !S.blocked.length;
  ub.innerHTML = S.blocked.map(([ip, host, mac, knocked, ven]) =>
    `<div class=row><div class=dname><b class=mono>${esc(ip)}</b>`
    + `<div class=sec>${esc(host)}${host && mac ? ' · ' : ''}${esc(mac)}`
    + `${ven ? ' · ' + esc(ven) : ''}</div></div><span class=sp></span>`
    + `<span class=sec>${knocked === null ? '' : ago(knocked)}</span>`
    + `<button class=btn data-ip="${esc(ip)}" data-nm="${esc(host)}" `
    + `onclick="addKnown(this)">${T.add}</button></div>`).join('');
```

CSS: `.bad{color:var(--red)}`. Правила `.blk`, `.blk .num`, `.blk .mini`, `.blk .knock`, `.mini` удаляются.

- [ ] **Step 3: Страница входа**

`LOGIN_T` — заменить блок `<style>` и разметку:

```html
<style>{{CSS}}
 body{max-width:20rem;margin:0 auto;padding-top:22vh}
 form{display:flex;gap:var(--s2);margin-top:var(--s3)}
 form input{flex:1}
 .err{color:var(--red);font-size:var(--f-sec);margin-top:var(--s2)}
</style>
<div class=panel>
 <h1>{{t.panelTitle}}</h1>
 <form method=post>
  <input class=field name=pw type=password autocomplete=current-password
    placeholder="{{t.password}}" autofocus>
  <button class="btn tinted">{{t.signIn}}</button>
 </form>
 {{MSG}}
</div>
```

Проверить в `login_page()`, что сообщение об ошибке заворачивается в `<p class=err>` — если сейчас там голый `<b>`, обернуть.

- [ ] **Step 4: Прогнать селфтест**

```bash
python3 panel.py --selftest
```

Ожидается `selftest ok` — селфтест рендерит логин с сообщением и без, и обе версии не должны содержать `{{`.

- [ ] **Step 5: Проверить руками**

Карточки чужаков и конфликтов — списки со строками, кнопка «Добавить» синяя, ⓘ у конфликта открывает нынешнее объяснение. Логин: панель по центру, ошибка красной строкой под полем. Проверить обе темы.

- [ ] **Step 6: Коммит**

```bash
git add panel.py
git commit -m "Чужаки, конфликты и вход в новом стиле"
```

---

### Task 13: Скриншоты и документация

**Files:**
- Modify: `docs/panel-ru.png`, `docs/panel-en.png`, `README.md`, `README.ru.md`, `CLAUDE.md`

- [ ] **Step 1: Снять скриншоты**

Поднять стенд, открыть в браузере шириной 1280, тёмная тема (как нынешние снимки), снять всю страницу. Русская версия — с `GWACL_DIR`, где `config.json` содержит `{"lang": "ru"}`, английская — `{"lang": "en"}`. Сохранить поверх `docs/panel-ru.png` и `docs/panel-en.png`.

- [ ] **Step 2: Поправить README.md**

Пройти по тексту и обновить всё, что описывает пропавшие элементы: колонки таблицы, кнопки «выключить/включить» в строке, выбор месяца в шапке, кнопку байпаса в шапке, поповер настроек. Добавить упоминание переключателя темы.

- [ ] **Step 3: Поправить README.ru.md**

Те же правки. README.ru.md — полный перевод, не пересказ: соответствие абзац в абзац.

- [ ] **Step 4: Поправить CLAUDE.md**

Абзац «Colours live in CSS variables declared twice in `CSS`: the dark `:root` and a `prefers-color-scheme: light` block» больше не верен. Заменить на описание нынешнего устройства: светлая в `:root`, тёмная один раз в `DARK` и подставляется в media-запрос (с `:not([data-theme=light])`) и в `:root[data-theme=dark]`; форма и кегль в `SHAPE`; литерал вне токенов ловится селфтестом; исключение — две меты `theme-color`.

- [ ] **Step 5: Прогнать всё**

```bash
python3 panel.py --selftest && python3 singbox_sub.py --selftest && bash -n install.sh
```

Ожидается `selftest ok` дважды и пустой вывод от `bash -n`.

- [ ] **Step 6: Коммит**

```bash
git add docs/panel-ru.png docs/panel-en.png README.md README.ru.md CLAUDE.md
git commit -m "Скриншоты и документация под новый интерфейс"
```

---

### Task 14: Версия

**Files:**
- Modify: `panel.py:62`

- [ ] **Step 1: Бампнуть**

`VERSION = "1.4.1"` → `VERSION = "1.5.0"`.

- [ ] **Step 2: Проверить**

```bash
python3 panel.py --version && python3 panel.py --selftest
```

Ожидается `1.5.0` и `selftest ok`.

- [ ] **Step 3: Коммит**

```bash
git add panel.py
git commit -m "version"
```

- [ ] **Step 4: Влить и пометить**

Тег ставится **после** влития в `main`: CI проверяет, что тег равен `VERSION`, на пуше тега.

```bash
git checkout main && git merge --no-ff panel-redesign
```

Тег и пуш — отдельным решением владельца репозитория, не частью этой задачи.

---

## Что не проверяется автоматически и требует глаз

`--selftest` ловит только структуру: наличие id, отсутствие `{{` в готовой странице, паритет ключей `STRINGS`, цветовой литерал мимо токенов. Всё остальное — стенд и браузер. Обязательный минимум перед вливанием:

- обе темы, каждая в двух состояниях — системная и выбранная руками;
- ширина 1280 и 375;
- раскрытая строка переживает три опроса подряд;
- ввод имени переживает опрос;
- открытый селект таймера не закрывается опросом;
- английская панель — на предмет строк, вылезающих из контролов.
