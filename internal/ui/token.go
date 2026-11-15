// SPDX-License-Identifier: AGPL-3.0-only

package ui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 32 random bytes, base64url without padding, so it goes into a URL and a cookie as it is
func NewToken() (token string, err error) {
	random := make([]byte, tokenBytes)
	_, err = rand.Read(random)

	if err != nil {
		err = fmt.Errorf("%w: %w", ErrToken, err)
		return
	}

	token = base64.RawURLEncoding.EncodeToString(random)
	return
}

// a token and a secret path, a code is made for --open only
func NewCredentials() (credentials *Credentials, err error) {
	token, err := NewToken()

	if err != nil {
		return
	}

	prefix, err := NewToken()

	if err != nil {
		return
	}

	credentials = &Credentials{
		Token:        token,
		Prefix:       prefix,
		mutex:        &sync.Mutex{},
		code:         "",
		codeDeadline: time.Time{},
	}
	return
}

// a new one-time code for the URL handed to the browser opener, it replaces an earlier one and is good for one first load within codeLifetime
func (credentials *Credentials) NewCode() (code string, err error) {
	code, err = NewToken()

	if err != nil {
		return
	}

	credentials.mutex.Lock()
	defer credentials.mutex.Unlock()
	credentials.code = code
	credentials.codeDeadline = time.Now().Add(codeLifetime)
	return
}

// true once for the code of NewCode before its deadline, it is gone after the first try that matches
func (credentials *Credentials) takeCode(given string) (isValid bool) {
	credentials.mutex.Lock()
	defer credentials.mutex.Unlock()
	isValid = (credentials.code != "") && time.Now().Before(credentials.codeDeadline) && isToken(given, credentials.code)

	if isValid {
		credentials.code = ""
		credentials.codeDeadline = time.Time{}
	}

	return
}

// the path the page and the api proxy are served under, and the Path of the cookie
func (credentials *Credentials) base() (path string) {
	path = "/" + credentials.Prefix + "/"
	return
}

// the URL decerter ui prints, it works as often as it is loaded; host is 127.0.0.1:<port>
func URL(host string, token string) (address string) {
	address = "http://" + host + "/?" + tokenParameter + "=" + token
	return
}

// the URL --open hands to the browser opener: the code in it works once, so the browser's command line holds no credential that is still good
func CodeURL(host string, code string) (address string) {
	address = "http://" + host + "/?" + codeParameter + "=" + code
	return
}

// every request needs the token cookie, the Host of the listener and the secret path, a request that changes something also its Origin; anything else is 403
// the first load with ?token= or ?code= on / sets the cookie and redirects to the secret path without it, so it leaves the address bar and the history
// browsers send a cookie to every port of 127.0.0.1: its Path is the secret path, so another server on loopback never gets it
func guard(next http.Handler, credentials *Credentials, host string, logger *slog.Logger) (handler http.Handler) {
	cookieName := cookieNameOf(host)
	base := credentials.base()
	page := http.StripPrefix(strings.TrimSuffix(base, "/"), next)
	handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(writer.Header())
		isFirstLoad, err := checkRequest(request, credentials, host, cookieName)

		if err != nil {
			logger.Warn("Refused ui request", "error", err, "method", request.Method, "path", logPath(request.URL.Path, base), "remoteAddress", request.RemoteAddr)
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}

		switch {
		case isFirstLoad:
			http.SetCookie(writer, &http.Cookie{
				Name:     cookieName,
				Value:    credentials.Token,
				Path:     base,
				HttpOnly: true,
				// plain http on loopback, a Secure cookie would never be sent
				Secure:   false,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(writer, request, base, http.StatusSeeOther)
		// the browser asks for it on its own, at the root and without the cookie; there is none
		case request.URL.Path == faviconPath:
			writer.WriteHeader(http.StatusNoContent)
		default:
			page.ServeHTTP(writer, request)
		}
	})
	return
}

// isFirstLoad when the request may go on and is the first load with the token or a code
// Host against DNS rebinding: a name that resolves to 127.0.0.1 is another origin to the browser, its requests carry that name
// Sec-Fetch-Site, when the browser sends it, refuses requests from other sites and from other ports of 127.0.0.1 (same-site to the browser)
func checkRequest(request *http.Request, credentials *Credentials, host string, cookieName string) (isFirstLoad bool, err error) {
	if request.Host != host {
		err = fmt.Errorf("%w %q", ErrHost, request.Host)
		return
	}

	fetchSite := request.Header.Get("Sec-Fetch-Site")

	switch fetchSite {
	case
		"",
		"same-origin",
		"none":
	default:
		err = fmt.Errorf("%w: Sec-Fetch-Site %q", ErrFetchSite, fetchSite)
		return
	}

	query := request.URL.Query()

	// the first load: only a GET of / takes the token or a code from the URL
	if query.Has(tokenParameter) || query.Has(codeParameter) {
		isGetRoot := (request.Method == http.MethodGet) && (request.URL.Path == "/") && (query.Has(tokenParameter) != query.Has(codeParameter))
		isFirstLoad = isGetRoot && (isToken(query.Get(tokenParameter), credentials.Token) || (query.Has(codeParameter) && credentials.takeCode(query.Get(codeParameter))))

		if !isFirstLoad {
			err = ErrBadToken
		}

		return
	}

	if (request.Method == http.MethodGet) && (request.URL.Path == faviconPath) {
		return
	}

	cookie, cookieErr := request.Cookie(cookieName)

	if (cookieErr != nil) || !isToken(cookie.Value, credentials.Token) {
		err = ErrCookie
		return
	}

	if !strings.HasPrefix(request.URL.Path, credentials.base()) {
		err = ErrPrefix
		return
	}

	switch request.Method {
	case
		http.MethodGet,
		http.MethodHead:
		return
	default:
	}

	// a request that changes something, defence in depth next to SameSite=Strict: browsers send Origin with every one of them
	origin := request.Header.Get("Origin")

	if ((origin == "") && (fetchSite != "same-origin")) || ((origin != "") && (origin != "http://"+host)) {
		err = fmt.Errorf("%w %q", ErrOrigin, origin)
		return
	}

	return
}

// the secret path stays out of the log, it is written <path>
func logPath(path string, base string) (logged string) {
	logged = path

	if rest, found := strings.CutPrefix(path, base); found {
		logged = "/<path>/" + rest
	}

	return
}

func isToken(given string, token string) (isValid bool) {
	isValid = subtle.ConstantTimeCompare([]byte(given), []byte(token)) == 1
	return
}

// decerter-ui-<port>: two decerter ui on two ports keep their own cookie
func cookieNameOf(host string) (name string) {
	_, port, err := net.SplitHostPort(host)

	if err != nil {
		port = ""
	}

	name = cookiePrefix + port
	return
}

// on every answer, the 403s and the proxied api answers too
func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
}
