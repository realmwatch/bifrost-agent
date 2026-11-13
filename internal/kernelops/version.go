package kernelops

// compareVersions orders two strings as dpkg orders versions (its verrevcmp):
// runs of non-digits compare character by character, with letters before
// other characters and "~" before everything, even the end; runs of digits
// compare as numbers. Kernel releases sort correctly this way:
// 6.8.0-45-generic < 6.8.0-49-generic < 6.8.0-100-generic.
func compareVersions(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			ac, bc := order(a), order(b)
			if ac != bc {
				return sign(ac - bc)
			}
			a, b = a[1:], b[1:]
		}
		for a != "" && a[0] == '0' {
			a = a[1:]
		}
		for b != "" && b[0] == '0' {
			b = b[1:]
		}
		diff := 0
		for a != "" && isDigit(a[0]) && b != "" && isDigit(b[0]) {
			if diff == 0 {
				diff = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		if a != "" && isDigit(a[0]) {
			return 1
		}
		if b != "" && isDigit(b[0]) {
			return -1
		}
		if diff != 0 {
			return sign(diff)
		}
	}
	return 0
}

// order is the weight of the first character of s in a non-digit run; an
// empty s (or one starting with a digit) weighs 0.
func order(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	switch {
	case isDigit(c):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
