package analyzers

import (
	"context"
	"fmt"

	"github.com/Liuchijang/FIR/internal/module"
)

func init() { module.RegisterAnalyzer(&browserCookiesParser{}) }

type browserCookiesParser struct{}

func (c *browserCookiesParser) Name() string     { return "browser_cookies_parser" }
func (c *browserCookiesParser) Category() string { return "browser" }
func (c *browserCookiesParser) Description() string {
	return "Parse browser cookies (metadata; values stay encrypted)"
}

// cookieSameSite is Chromium's CookieSameSite. -1 is the state for a cookie
// stored before the attribute existed, which is not the same as SameSite=None.
var cookieSameSite = map[int64]string{
	-1: "Unspecified",
	0:  "None",
	1:  "Lax",
	2:  "Strict",
}

// cookiePriority is Chromium's CookiePriority, which decides eviction order.
var cookiePriority = map[int64]string{
	0: "Low",
	1: "Medium",
	2: "High",
}

// cookieSourceScheme records whether the cookie was set over a secure origin.
var cookieSourceScheme = map[int64]string{
	0: "Unset",
	1: "NonSecure",
	2: "Secure",
}

// chromiumCookiesTable covers every Chrome cookie schema in circulation.
//
// FIR does not decrypt cookie values. Since Chrome 80 they are wrapped in
// AES-256-GCM under a key that lives in Local State, and the metadata is what
// answers the usual questions anyway: which sites the browser held state for,
// when each cookie was created, and when it was last sent.
//
// The encrypted blob is still exported, as hex, with a column saying which
// scheme wrapped it. The collector keeps the cookie store itself byte-for-byte,
// so a decision to recover values later is not foreclosed by anything here.
var chromiumCookiesTable = browserTable{
	name:    "cookies",
	orderBy: "creation_utc",
	columns: []browserColumn{
		rawColumn("host_key"),
		rawColumn("top_frame_site_key"),
		rawColumn("name"),
		rawColumn("path"),
		chromiumTimeColumn("creation_utc", "CreationUTC"),
		chromiumTimeColumn("expires_utc", "ExpiresUTC"),
		chromiumTimeColumn("last_access_utc", "LastAccessUTC"),
		chromiumTimeColumn("last_update_utc", "LastUpdateUTC"),
		boolColumn("is_secure", "IsSecure"),
		boolColumn("is_httponly", "IsHttpOnly"),
		boolColumn("has_expires", "HasExpires"),
		boolColumn("is_persistent", "IsPersistent"),
		rawColumn("samesite"),
		enumColumn("samesite", "SameSiteResolved", cookieSameSite),
		rawColumn("priority"),
		enumColumn("priority", "PriorityResolved", cookiePriority),
		rawColumn("source_scheme"),
		enumColumn("source_scheme", "SourceSchemeResolved", cookieSourceScheme),
		rawColumn("source_port"),
		rawColumn("is_same_party"),
		// Plaintext on very old profiles and on Linux without a keyring.
		rawColumn("value"),
		rawColumn("encrypted_value"),
		encryptionStateColumn("encrypted_value", "ValueEncryption"),
	},
}

// firefoxCookiesTable reads cookies.sqlite, where values were never encrypted.
var firefoxCookiesTable = browserTable{
	name:    "moz_cookies",
	orderBy: "creationTime",
	columns: []browserColumn{
		rawColumn("host"),
		rawColumn("name"),
		rawColumn("path"),
		rawColumn("value"),
		namedColumn("creationTime", "CreationUTC", func(value any) string {
			return firefoxTimeString(browserInt(value))
		}),
		namedColumn("lastAccessed", "LastAccessedUTC", func(value any) string {
			return firefoxTimeString(browserInt(value))
		}),
		// expiry is seconds here while the other two are microseconds.
		unixSecondsColumn("expiry", "ExpiresUTC"),
		boolColumn("isSecure", "IsSecure"),
		boolColumn("isHttpOnly", "IsHttpOnly"),
		rawColumn("sameSite"),
		enumColumn("sameSite", "SameSiteResolved", cookieSameSite),
		rawColumn("originAttributes"),
	},
}

func (c *browserCookiesParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create browser cookies parser output dir: %w", err))
	}

	// Chrome moved the cookie store under Network/ in v96 and left the old path
	// behind on upgraded profiles, so both are read; whichever is absent simply
	// contributes nothing. Extension Cookies is a separate store for
	// extension-origin cookies.
	return browserAnalyzeSQLite(ctx, req, outDir, []browserExport{
		{database: "Network/Cookies", tables: []browserExportTable{
			{suffix: "cookies.csv", table: chromiumCookiesTable},
		}},
		{database: "Cookies", tables: []browserExportTable{
			{suffix: "cookies_legacy.csv", table: chromiumCookiesTable},
		}},
		{database: "Extension Cookies", tables: []browserExportTable{
			{suffix: "extension_cookies.csv", table: chromiumCookiesTable},
		}},
		{database: "cookies.sqlite", tables: []browserExportTable{
			{suffix: "cookies.csv", table: firefoxCookiesTable},
		}},
	})
}
