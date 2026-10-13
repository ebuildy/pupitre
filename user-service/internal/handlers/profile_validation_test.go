package handlers

import "testing"

// TestValidateUsername checks that the username rules accept ordinary
// names and reject HTML-dangerous payloads.
func TestValidateUsername(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		ok    bool
	}{
		{"plain", "alice", true},
		{"with separators", "al_ice.1-x", true},
		{"unicode letters", "élève", true},
		{"digits", "user123", true},
		{"max length", repeatRune('a', usernameMaxLen), true},
		{"too long", repeatRune('a', usernameMaxLen+1), false},
		{"img tag payload", "<img src=x onerror=alert(1)>", false},
		{"angle bracket", "a<b", false},
		{"double quote", `a"b`, false},
		{"single quote", "a'b", false},
		{"space", "a b", false},
		{"slash", "a/b", false},
		{"backtick", "a`b", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, ok := validateUsername(tc.input); ok != tc.ok {
				t.Fatalf("validateUsername(%q) ok = %v, want %v", tc.input, ok, tc.ok)
			}
		})
	}
}

// TestValidateEmailFormat checks the email syntax guard.
func TestValidateEmailFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		ok    bool
	}{
		{"user@example.com", true},
		{"admin@pupitre.local", true},
		{"a+tag@sub.example.co.uk", true},
		{"", false},
		{"notanemail", false},
		{"<script>@x.com", false},
		{"Name <user@example.com>", false},
		{"user@", false},
	}

	for _, tc := range cases {
		if got := validateEmailFormat(tc.input); got != tc.ok {
			t.Errorf("validateEmailFormat(%q) = %v, want %v", tc.input, got, tc.ok)
		}
	}
}

// TestValidateAvatarURL checks that avatars may be https URLs or short
// emoji labels, and that attribute break-out payloads are rejected.
func TestValidateAvatarURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		ok    bool
	}{
		{"", true}, // clears the avatar
		{"https://cdn.example.com/a.png", true},
		{"🎉", true},                             // emoji avatar
		{"🐙🚀", true},                            // short emoji label
		{"http://cdn.example.com/a.png", false}, // not https
		{"javascript:alert(1)", false},
		{`https://x/" onerror="alert(1)`, false}, // attribute break-out
		{"https://x/ onerror=alert(1)", false},   // whitespace
		{"//cdn.example.com/a.png", false},       // long non-url label
		{"ftp://x/a.png", false},
		{"<img src=x onerror=alert(1)>", false}, // tag payload
		{`a"b`, false},                          // quote
	}

	for _, tc := range cases {
		if _, ok := validateAvatarURL(tc.input); ok != tc.ok {
			t.Errorf("validateAvatarURL(%q) ok = %v, want %v", tc.input, ok, tc.ok)
		}
	}
}

// repeatRune returns a string of n copies of r.
func repeatRune(r rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = r
	}

	return string(b)
}
