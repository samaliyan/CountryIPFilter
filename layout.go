package main

// Window layout in 96-DPI units. Kept apart from the Win32 code so the same
// numbers drive the real window and the mock-up used to check text fit.
// The window is mirrored (right-to-left): X is measured from the right edge.

type Box struct{ X, Y, W, H int }

func (b Box) Visible() bool { return b.W > 0 }

type ProblemRow struct {
	Text, Button, Bar Box
}

type Layout struct {
	ClientW, ClientH int
	Banner           Box
	Title, Desc      Box
	Progress         Box
	Main             Box
	Second           []Box // turn off / refresh / details / copy, in that order (hidden: W == 0)
	Sep              []int // y of thin separator lines
	CountriesHead    Box
	CountryList      Box
	CountryCombo     Box
	AddCountry       Box
	RemoveCountry    Box
	PortsHead        Box
	PortList         Box
	AddLabel         Box
	ProtoCombo       Box
	PortCombo        Box
	AddButton        Box
	AddApp           Box
	RemoveButton     Box
	ProbHead         Box
	CopyProb         Box // copies the text of every problem
	NoProb           Box
	Rows             []ProblemRow
	Hidden           int // problems that did not fit
	Info             Box
	Lang             Box // switches the language (next to the info line)
	Log              Box
}

const (
	layoutW     = 720
	maxRows     = 6
	rowTextW    = 508
	rowButtonW  = 164
	detailsLogH = 400
	// size of the window before the first look (close to the usual "off" screen)
	firstClientH = 480
)

// Second-row button indexes.
const (
	secOff = iota
	secRefresh
	secDetails
	secCopy
)

// computeLayout places everything. measure returns the height of a text
// wrapped to a width (both in 96-DPI units). maxH is the tallest client
// area that fits on the screen.
func computeLayout(v View, haveView, details, busy bool, measure func(text string, width int) int, maxH int) Layout {
	L := Layout{ClientW: layoutW}
	descH := 18
	if haveView { // same height while busy, so the window does not jump
		descH = measure(v.Desc, 672)
		if descH < 18 {
			descH = 18
		}
	}
	L.Title = Box{24, 18, 672, 30}
	L.Desc = Box{24, 52, 672, descH}
	bottom := 52 + descH + 14
	if busy {
		L.Progress = Box{24, 52 + descH + 4, 672, 5}
	}
	L.Banner = Box{8, 8, 704, bottom - 8}
	y := bottom + 12
	if !haveView {
		// first look: only the banner, in a window of the usual size
		L.ClientH = firstClientH
		L.Second = make([]Box, 4)
		return L
	}

	// space around the separator lines (less on a small screen)
	gap, pad := 14, 10
	if maxH > 0 && maxH < 640 {
		gap, pad = 6, 4
	}

	// ---- action row: main button, then smaller buttons to its left
	L.Main = Box{16, y, 250, 40}
	L.Second = make([]Box, 4)
	x := L.Main.X + L.Main.W + 12
	place := func(i, w int) {
		L.Second[i] = Box{x, y + 4, w, 32}
		x += w + 8
	}
	if details {
		L.Main.W = 0
		x = 16
		place(secDetails, 120)
		place(secCopy, 120)
	} else {
		if v.CanOff {
			place(secOff, 170)
		}
		if v.Action != ActRefresh {
			place(secRefresh, 120)
		}
		place(secDetails, 120)
	}
	y += 40 + gap
	L.Sep = append(L.Sep, y)
	y += pad

	if details {
		h := detailsLogH
		if y+h+44 > maxH && maxH > 0 {
			h = maxH - y - 44
		}
		if h < 120 {
			h = 120
		}
		L.Log = Box{16, y, 688, h}
		y += h + 10
		L.Info, L.Lang = Box{16, y, 600, 22}, Box{624, y - 3, 80, 26}
		L.ClientH = y + 30
		return L
	}

	// ---- countries
	L.CountriesHead = Box{16, y, 300, 22}
	y += 26
	L.CountryList = Box{16, y, 448, 92}
	L.CountryCombo = Box{480, y, 224, 320}
	L.AddCountry = Box{480, y + 31, 224, 28}
	L.RemoveCountry = Box{480, y + 63, 224, 28}
	y += 92 + gap
	L.Sep = append(L.Sep, y)
	y += pad

	// ---- ports and programs
	L.PortsHead = Box{16, y, 300, 22}
	y += 26
	listH := 26 + 22*len(v.Rows)
	if listH < 26+22*6 || (maxH > 0 && maxH < 720) {
		listH = 26 + 22*6 // also on a small screen: room for the problems
	}
	if listH > 26+22*8 {
		listH = 26 + 22*8
	}
	L.PortList = Box{16, y, 448, listH}
	L.AddLabel = Box{480, y, 224, 20}
	L.ProtoCombo = Box{480, y + 22, 70, 120}
	L.PortCombo = Box{558, y + 22, 146, 320}
	L.AddButton = Box{480, y + 56, 224, 28}
	L.AddApp = Box{480, y + 90, 224, 28}
	L.RemoveButton = Box{480, y + 124, 224, 28}
	y += listH + gap
	L.Sep = append(L.Sep, y)
	y += pad

	// ---- problems (not shown while protection is off and nothing is wrong,
	// nor when the state could not be read)
	small := maxH > 0 && maxH < 640 // nothing to fix: the banner already says so
	if (!v.On || v.Unknown || small) && len(v.Problems) == 0 {
		L.Info, L.Lang = Box{16, y, 600, 22}, Box{624, y - 3, 80, 26}
		L.ClientH = y + 30
		return L
	}
	L.ProbHead = Box{16, y, 688, 22}
	if len(v.Problems) > 0 {
		L.ProbHead.W = 540
		L.CopyProb = Box{layoutW - 16 - 150, y - 4, 150, 26}
	}
	y += 28
	if len(v.Problems) == 0 {
		L.NoProb = Box{16, y, 688, 22}
		y += 30
	}
	for i, p := range v.Problems {
		w := rowTextW
		if p.Button == "" {
			w = layoutW - 20 - 16 // no button: the text may use the whole row
		}
		h := measure(p.Text, w)
		if h < 32 {
			h = 32
		}
		rowH := h + 14
		// keep room for the info line (the first problem is always shown)
		if i >= maxRows || (i > 0 && maxH > 0 && y+rowH+44 > maxH) {
			L.Hidden = len(v.Problems) - i
			break
		}
		r := ProblemRow{Bar: Box{8, y, 4, h}, Text: Box{20, y, w, h}}
		if p.Button != "" {
			r.Button = Box{layoutW - 16 - rowButtonW, y, rowButtonW, 30}
		}
		L.Rows = append(L.Rows, r)
		y += rowH
	}
	y += 2
	L.Sep = append(L.Sep, y)
	y += 8
	L.Info, L.Lang = Box{16, y, 600, 22}, Box{624, y - 3, 80, 26}
	L.ClientH = y + 30
	return L
}

// approxMeasure estimates wrapped text height without a screen (tests and
// mock-ups): Persian at 9pt Segoe UI is about 6 px per character, 17 px a line.
func approxMeasure(text string, width int) int {
	lines := 0
	for _, para := range splitLines(text) {
		n := len([]rune(para))
		l := (n*6 + width - 1) / width
		if l < 1 {
			l = 1
		}
		lines += l
	}
	return lines * 17
}

func splitLines(s string) []string {
	var out []string
	cur := []rune{}
	for _, r := range s {
		switch r {
		case '\r':
		case '\n':
			out = append(out, string(cur))
			cur = cur[:0]
		default:
			cur = append(cur, r)
		}
	}
	return append(out, string(cur))
}
