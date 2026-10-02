#!/usr/bin/env python3
"""Draws the window exactly with the Win32 coordinates of gui_windows.go
(96 DPI), using DejaVu Sans (wider than Tahoma, so a worst case) to check
that every text fits."""
import json, sys
from PIL import Image, ImageDraw, ImageFont

F = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
font = ImageFont.truetype(F, 12, layout_engine=ImageFont.Layout.RAQM)
head = ImageFont.truetype(FB, 13, layout_engine=ImageFont.Layout.RAQM)
bold = ImageFont.truetype(FB, 14, layout_engine=ImageFont.Layout.RAQM)
big = ImageFont.truetype(FB, 19, layout_engine=ImageFont.Layout.RAQM)

PAL = {0: ((238, 240, 243), (55, 60, 70)), 1: ((228, 245, 233), (19, 96, 47)),
       2: ((255, 243, 222), (122, 67, 0)), 3: ((253, 232, 232), (153, 27, 27))}
W, H = 720, 612
overflow = []


RTL = True


def rx(x, w):  # mirrored window (Persian): x measured from the right
    if not RTL:
        return x
    return W - x - w


def wrap(text, f, width):
    lines, cur = [], ""
    for word in text.split(" "):
        t = (cur + " " + word).strip()
        if f.getlength(t) <= width:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def text(d, x, y, w, h, s, f, color=(20, 20, 20), center=False, name=""):
    lines = wrap(s, f, w - 4)
    lh = f.size + 4
    if len(lines) * lh > h + 2:
        overflow.append(f"{name}: {len(lines)} lines in {h}px: {s[:60]}")
    for i, line in enumerate(lines):
        lw = f.getlength(line)
        X = rx(x, w) + (w - lw) / 2 if center else (rx(x, w) + w - lw if RTL else rx(x, w))
        if y + i * lh < y + h + 2:
            d.text((X, y + i * lh), line, font=f, fill=color, direction="rtl" if RTL else "ltr")


def button(d, x, y, w, h, s, f=font, default=False):
    X = rx(x, w)
    d.rounded_rectangle([X, y, X + w, y + h], 3, fill=(253, 253, 253), outline=(0, 120, 215) if default else (173, 173, 173), width=2 if default else 1)
    if f.getlength(s) > w - 8:
        overflow.append(f"button too narrow: {s}")
    text(d, x, y + (h - f.size) / 2 - 2, w, f.size + 6, s, f, center=True, name="btn")


STATE = {0: (90, 96, 106), 1: (21, 128, 61), 2: (194, 110, 0), 3: (200, 30, 30)}
BUSY = ((232, 240, 254), (24, 80, 170))



def vis(b):
    return b["W"] > 0


def render(v, L, path, TX, states, countries, combo):
    global W
    W = L["ClientW"]
    H = L["ClientH"]
    im = Image.new("RGB", (W, H), (255, 255, 255))
    d = ImageDraw.Draw(im)
    bg, fg = PAL[v["Level"]]
    b = L["Banner"]
    d.rectangle([rx(b["X"], b["W"]), b["Y"], rx(b["X"], b["W"]) + b["W"], b["Y"] + b["H"]], fill=bg)
    for k, f in (("Title", big), ("Desc", font)):
        bb = L[k]
        text(d, bb["X"], bb["Y"], bb["W"], bb["H"], v[k], f, fg, name=k)
    for y in L["Sep"] or []:
        d.line([16, y, W - 16, y], fill=(226, 229, 234))
    m = L["Main"]
    if vis(m):
        button(d, m["X"], m["Y"], m["W"], m["H"], v["Main"], bold, True)
    for i, sb in enumerate(L["Second"]):
        if vis(sb):
            button(d, sb["X"], sb["Y"], sb["W"], sb["H"], [TX["off"], TX["check"], TX["details"], TX["copy"]][i])
    ch = L["CountriesHead"]
    if vis(ch):
        text(d, ch["X"], ch["Y"], ch["W"] + 300, ch["H"], TX["countries"], head, name="countrieshead")
        lb = L["CountryList"]
        X = rx(lb["X"], lb["W"])
        d.rectangle([X, lb["Y"], X + lb["W"], lb["Y"] + lb["H"]], fill="white", outline=(130, 135, 144))
        for i, c in enumerate(countries):
            text(d, lb["X"] + 6, lb["Y"] + 3 + i * 17, lb["W"] - 12, 16, c, font, name="country")
        cb = L["CountryCombo"]
        X = rx(cb["X"], cb["W"])
        d.rectangle([X, cb["Y"], X + cb["W"], cb["Y"] + 24], fill=(250, 250, 250), outline=(130, 135, 144))
        text(d, cb["X"] + 6, cb["Y"] + 4, cb["W"] - 26, 18, combo, font, name="combo")
        for k, t in (("AddCountry", "addCountry"), ("RemoveCountry", "remCountry")):
            b2 = L[k]
            button(d, b2["X"], b2["Y"], b2["W"], b2["H"], TX[t])
    hb = L["PortsHead"]
    if vis(hb):
        text(d, hb["X"], hb["Y"], hb["W"], hb["H"], TX["ports"], head, name="portshead")
        lb = L["PortList"]
        X = rx(lb["X"], lb["W"])
        d.rectangle([X, lb["Y"], X + lb["W"], lb["Y"] + lb["H"]], fill="white", outline=(130, 135, 144))
        cols = [(72, TX["item"]), (116, TX["service"]), (238, TX["state"])]
        cx = lb["X"] + 2
        d.rectangle([X + 1, lb["Y"] + 1, X + lb["W"] - 1, lb["Y"] + 24], fill=(247, 248, 250))
        for w, t in cols:
            text(d, cx + 4, lb["Y"] + 4, w - 8, 18, t, font, name="colhead")
            cx += w
        for i, r in enumerate(v["Rows"] or []):
            y = lb["Y"] + 28 + i * 22
            cx = lb["X"] + 2
            for j, (w, _) in enumerate(cols):
                t = [r["Item"], r["Service"], states[i]][j]
                f = boldsmall if j == 2 else font
                col = STATE[r["Level"]] if j == 2 else (33, 37, 41)
                text(d, cx + 4, y, w - 8, 18, t, f, col, name="cell")
                cx += w
        a = L["AddLabel"]
        text(d, a["X"], a["Y"], a["W"], a["H"], TX["addLabel"], font)
        pc = L["ProtoCombo"]
        X = rx(pc["X"], pc["W"])
        d.rectangle([X, pc["Y"], X + pc["W"], pc["Y"] + 24], fill=(250, 250, 250), outline=(130, 135, 144))
        text(d, pc["X"] + 6, pc["Y"] + 4, pc["W"] - 26, 18, "TCP", font, name="proto")
        cb = L["PortCombo"]
        X = rx(cb["X"], cb["W"])
        d.rectangle([X, cb["Y"], X + cb["W"], cb["Y"] + 24], fill="white", outline=(130, 135, 144))
        text(d, cb["X"] + 20, cb["Y"] + 4, cb["W"] - 24, 18, TX["cue"], font, (150, 150, 150))
        for k, t in (("AddButton", "add"), ("AddApp", "addApp"), ("RemoveButton", "remove")):
            b2 = L[k]
            button(d, b2["X"], b2["Y"], b2["W"], b2["H"], TX[t])
    ph = L["ProbHead"]
    probs = v["Problems"] or []
    if vis(ph):
        t = TX["problemsN"] if probs else TX["problems"]
        text(d, ph["X"], ph["Y"], ph["W"], ph["H"], t, head)
    nb = L["NoProb"]
    if vis(nb):
        text(d, nb["X"], nb["Y"], nb["W"], nb["H"], TX["noProb"], font, STATE[1])
    for i, r in enumerate(L["Rows"] or []):
        p = probs[i]
        bar = r["Bar"]
        d.rectangle([rx(bar["X"], bar["W"]), bar["Y"], rx(bar["X"], bar["W"]) + bar["W"], bar["Y"] + bar["H"]], fill=STATE[3] if p["Severe"] else STATE[2])
        tb = r["Text"]
        yy = tb["Y"]
        used = 0
        for part in p["Text"].split("\r\n"):
            n = max(1, len(wrap(part, font, tb["W"] - 4)))
            text(d, tb["X"], yy, tb["W"], n * 16, part, font, (33, 37, 41), name=f"problem{i}")
            yy += n * 16
            used += n * 16
        if used > tb["H"] + 2:
            overflow.append(f"problem{i}: needs {used}px, has {tb['H']}")
        bb = r["Button"]
        if vis(bb):
            button(d, bb["X"], bb["Y"], bb["W"], bb["H"], p["Button"])
    ib = L["Info"]
    text(d, ib["X"], ib["Y"], ib["W"], ib["H"], v["Info"], small, (100, 106, 116), name="info")
    lb = L.get("Lang")
    if lb and vis(lb):
        button(d, lb["X"], lb["Y"], lb["W"], lb["H"], TX["lang"])
    # a simple title bar, to show the name and version
    full = Image.new("RGB", (W, H + 30), (255, 255, 255))
    fd = ImageDraw.Draw(full)
    fd.rectangle([0, 0, W, 30], fill=(243, 243, 243))
    tw = font.getlength(TX["title"])
    fd.text(((W - tw - 12) if RTL else 12, 8), TX["title"], font=font, fill=(30, 30, 30), direction="rtl" if RTL else "ltr")
    full.paste(im, (0, 30))
    full.save(path)


boldsmall = ImageFont.truetype(FB, 12, layout_engine=ImageFont.Layout.RAQM)
small = ImageFont.truetype(F, 11, layout_engine=ImageFont.Layout.RAQM)
views = json.load(open(sys.argv[1]))
for name, x in sorted(views.items()):
    RTL = x["RTL"]
    render(x["View"], x["Layout"], f"{sys.argv[2]}/{name}.png", x["Text"], x["States"] or [], x["Countries"] or [], x["Combo"])
print("\n".join(overflow) if overflow else "all texts fit")
