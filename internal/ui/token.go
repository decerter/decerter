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

// the URL decerter ui prints; host is 127.0.0.1:<port>
func URL(host string, token string) (address string) {
	address = "http://" + host + "/?" + tokenParameter + "=" + token
	return
}

// every request needs the token and the Host of the listener, a request that changes something also its Origin; anything else is 403
// the first load with ?token= on / sets the cookie and redirects to / without the token, so it leaves the address bar and the history
func guard(next http.Handler, token string, host string, logger *slog.Logger) (handler http.Handler) {
	cookieName := cookieNameOf(host)
	handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(writer.Header())
		err := checkRequest(request, token, host, cookieName)

		if err != nil {
			logger.Warn("Refused ui request", "error", err, "method", request.Method, "path", request.URL.Path, "remoteAddress", request.RemoteAddr)
			http.Error(writer, "forbidden", http.StatusForbidden)
			return
		}

		if request.URL.Query().Has(tokenParameter) {
			http.SetCookie(writer, &http.Cookie{
				Name:     cookieName,
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				// plain http on loopback, a Secure cookie would never be sent
				Secure:   false,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(writer, request, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(writer, request)
	})
	return
}

// nil when the request may go on
// Host against DNS rebinding: a name that resolves to 127.0.0.1 is another origin to the browser, its requests carry that name
// Sec-Fetch-Site, when the browser sends it, refuses requests from other sites and from other ports of 127.0.0.1 (same-site to the browser)
func checkRequest(request *http.Request, token string, host string, cookieName string) (err error) {
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

	// the first load: only a GET of / takes the token from the URL
	if request.URL.Query().Has(tokenParameter) {
		if (request.Method != http.MethodGet) || (request.URL.Path != "/") || !isToken(request.URL.Query().Get(tokenParameter), token) {
			err = ErrBadToken
		}

		return
	}

	cookie, cookieErr := request.Cookie(cookieName)

	if (cookieErr != nil) || !isToken(cookie.Value, token) {
		err = ErrCookie
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
