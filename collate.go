package main

// lessName sorts names the way a reader expects: Persian in the order of
// the Persian alphabet (Unicode order puts پ چ ژ ک گ ی at the end), English
// without regard to case.

import "strings"

const faAlphabet = "آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی"

var faOrder = func() map[rune]int {
	m := map[rune]int{}
	for i, r := range []rune(faAlphabet) {
		m[r] = i + 1
	}
	for from, to := range map[rune]rune{'ك': 'ک', 'ي': 'ی', 'ى': 'ی', 'ئ': 'ی', 'أ': 'ا', 'إ': 'ا', 'ٱ': 'ا', 'ؤ': 'و', 'ة': 'ه', 'ۀ': 'ه'} {
		m[from] = m[to]
	}
	return m
}()

func collateKey(s string) []int {
	var k []int
	for _, r := range strings.ToLower(s) {
		switch {
		case r == '‌' || r == 'ٔ' || r == 'ـ' || (r >= 'ً' && r <= 'ْ'):
			continue // ZWNJ, hamza above, tatweel, short vowels: not letters of their own
		case r == ' ':
			k = append(k, 0)
		case faOrder[r] > 0:
			k = append(k, 100+faOrder[r])
		default:
			k = append(k, 1000+int(r))
		}
	}
	return k
}

func lessName(a, b string) bool {
	ka, kb := collateKey(a), collateKey(b)
	for i := 0; i < len(ka) && i < len(kb); i++ {
		if ka[i] != kb[i] {
			return ka[i] < kb[i]
		}
	}
	return len(ka) < len(kb)
}
