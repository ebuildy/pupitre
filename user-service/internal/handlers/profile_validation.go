package handlers

import (
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Username / avatar validation rules. These close the stored-XSS vector
// (GHSA-xwm2-h7v2-47f2): user-controlled profile fields used to be stored
// verbatim and later rendered into innerHTML by the frontend. Validation
// here is the authoritative guard; frontend escaping is defense in depth.
const (
	// usernameMaxLen bounds the stored username (runes, not bytes).
	usernameMaxLen = 32
	// avatarURLMaxLen bounds a stored avatar URL.
	avatarURLMaxLen = 2048

	// avatarEmojiMaxLen bounds a non-URL avatar (an emoji / short label).
	avatarEmojiMaxLen = 16

	authMsgUsernameTooLong = "Username must be at most 32 characters"
	authMsgUsernameChars   = "Username may only contain letters, numbers and . _ -"
	authMsgEmailInvalid    = "A valid email address is required"
	authMsgAvatarInvalid   = "Avatar must be an https:// URL or a short emoji"
)

// avatarUnsafeChars are the characters that could break out of an HTML
// attribute or start a tag; they are rejected in any avatar value.
const avatarUnsafeChars = " \t\r\n\"'<>\\`"

// usernamePattern allows Unicode letters/numbers plus a small set of
// separators. It intentionally rejects anything that could start an HTML
// tag or attribute break-out (`<`, `>`, `"`, `'`, `/`, whitespace, ...).
var usernamePattern = regexp.MustCompile(`^[\p{L}\p{N}._-]+$`)

// validateUsername reports an HTTP-facing message when uname is not an
// acceptable username, or ok == true when it is. Callers are expected to
// have trimmed surrounding whitespace and handled the minimum-length and
// uniqueness checks that already exist.
func validateUsername(uname string) (string, bool) {
	if utf8.RuneCountInString(uname) > usernameMaxLen {
		return authMsgUsernameTooLong, false
	}

	if !usernamePattern.MatchString(uname) {
		return authMsgUsernameChars, false
	}

	return "", true
}

// validateEmailFormat reports whether email is a syntactically valid,
// single email address. It does not check deliverability.
func validateEmailFormat(email string) bool {
	addr, err := mail.ParseAddress(strings.TrimSpace(email))
	if err != nil {
		return false
	}

	// mail.ParseAddress accepts display names ("Name <a@b>"); require the
	// address to equal the input so "x <a@b>" style values are rejected.
	return addr.Address == strings.TrimSpace(email)
}

// validateAvatarURL reports an HTTP-facing message when raw is not an
// acceptable avatar, or ok == true when it is. An avatar is either empty
// ("clear the avatar"), an https:// URL, or a short emoji/label. In every
// case characters that could break out of an HTML attribute are rejected,
// so the value is safe once escaped by the frontend.
func validateAvatarURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", true
	}

	// Reject control characters, whitespace and quotes outright: these are
	// what let a value break out of an src="..." attribute.
	if strings.ContainsAny(raw, avatarUnsafeChars) {
		return authMsgAvatarInvalid, false
	}

	// A URL (anything with a scheme) must be https.
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "http") {
		if len(raw) > avatarURLMaxLen {
			return authMsgAvatarInvalid, false
		}

		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return authMsgAvatarInvalid, false
		}

		return "", true
	}

	// Otherwise treat it as a short emoji / label.
	if utf8.RuneCountInString(raw) > avatarEmojiMaxLen {
		return authMsgAvatarInvalid, false
	}

	return "", true
}
