package analyzers

import (
	"context"
	"fmt"
	"strings"

	"github.com/Liuchijang/Tyto/internal/module"
)

func init() { module.RegisterAnalyzer(&browserCredentialsParser{}) }

type browserCredentialsParser struct{}

func (c *browserCredentialsParser) Name() string     { return "browser_credentials_parser" }
func (c *browserCredentialsParser) Category() string { return "browser" }
func (c *browserCredentialsParser) Description() string {
	return "Parse saved logins and autofill (passwords stay encrypted)"
}

// This is a separate module from the other browser analyzers on purpose. Saved
// credentials and autofill are the most sensitive thing a browser profile holds —
// names, addresses, card hints, which sites an account exists on — so an
// operator has to be able to run a browser triage without collecting them.

// chromiumLoginsTable reads the Login Data database.
//
// Tyto does not recover passwords. password_value is exported as hex with a column
// naming the scheme that wrapped it, and the collector keeps Login Data itself
// intact, so nothing here prevents recovery by other means later.
//
// What the table establishes on its own is usually the investigative question
// anyway: which sites an account was saved for, when it was saved, when it was
// last used, and how often — an account appearing here for a service the user
// denies using is a finding regardless of whether the password is readable.
var chromiumLoginsTable = browserTable{
	name:    "logins",
	orderBy: "date_created",
	columns: []browserColumn{
		rawColumn("origin_url"),
		rawColumn("action_url"),
		rawColumn("signon_realm"),
		rawColumn("username_element"),
		rawColumn("username_value"),
		rawColumn("password_element"),
		rawColumn("password_value"),
		encryptionStateColumn("password_value", "PasswordEncryption"),
		chromiumTimeColumn("date_created", "DateCreatedUTC"),
		chromiumTimeColumn("date_last_used", "DateLastUsedUTC"),
		chromiumTimeColumn("date_password_modified", "DatePasswordModifiedUTC"),
		chromiumTimeColumn("date_synced", "DateSyncedUTC"),
		rawColumn("times_used"),
		// Set when the user told Chrome never to save for this site, which is
		// itself a record that they visited and were prompted.
		boolColumn("blacklisted_by_user", "BlacklistedByUser"),
		rawColumn("scheme"),
		rawColumn("display_name"),
		rawColumn("federation_url"),
		rawColumn("skip_zero_click"),
		rawColumn("generation_upload_status"),
		rawColumn("id"),
	},
}

// chromiumAutofillTable reads Web Data. Unlike logins these values are stored in
// the clear: every string the user typed into a form that Chrome remembered.
var chromiumAutofillTable = browserTable{
	name:    "autofill",
	orderBy: "date_created",
	columns: []browserColumn{
		rawColumn("name"),
		rawColumn("value"),
		rawColumn("value_lower"),
		rawColumn("count"),
		unixSecondsColumn("date_created", "DateCreatedUTC"),
		unixSecondsColumn("date_last_used", "DateLastUsedUTC"),
	},
}

// chromiumAutofillProfileTable holds the structured identity Chrome offers for
// address forms.
var chromiumAutofillProfileTable = browserTable{
	name:    "autofill_profiles",
	orderBy: "date_modified",
	columns: []browserColumn{
		rawColumn("guid"),
		rawColumn("company_name"),
		rawColumn("street_address"),
		rawColumn("dependent_locality"),
		rawColumn("city"),
		rawColumn("state"),
		rawColumn("zipcode"),
		rawColumn("country_code"),
		unixSecondsColumn("use_date", "UseDateUTC"),
		rawColumn("use_count"),
		unixSecondsColumn("date_modified", "DateModifiedUTC"),
		rawColumn("language_code"),
		rawColumn("label"),
	},
}

// firefoxFormHistoryTable is the Firefox equivalent of Chrome's autofill table.
var firefoxFormHistoryTable = browserTable{
	name:    "moz_formhistory",
	orderBy: "firstUsed",
	columns: []browserColumn{
		rawColumn("fieldname"),
		rawColumn("value"),
		rawColumn("timesUsed"),
		namedColumn("firstUsed", "FirstUsedUTC", func(value any) string {
			return firefoxTimeString(browserInt(value))
		}),
		namedColumn("lastUsed", "LastUsedUTC", func(value any) string {
			return firefoxTimeString(browserInt(value))
		}),
		rawColumn("guid"),
	},
}

func (c *browserCredentialsParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create browser credentials parser output dir: %w", err))
	}

	// Firefox keeps saved logins in a JSON file, not SQLite, so it is exported
	// alongside rather than through the table machinery.
	var extra []module.FileInfo
	var warnings []string
	if sources, err := resolveBrowserProfileSources(req); err == nil {
		for _, source := range sources {
			if source.Profile.Family != "firefox" {
				continue
			}
			fi, err := exportFirefoxLogins(ctx, outDir, source.Profile)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: logins.json %v", browserProfileLabel(source.Profile), err))
				continue
			}
			if fi.Path != "" {
				extra = append(extra, fi)
			}
		}
	}

	result := browserAnalyzeSQLite(ctx, req, outDir, []browserExport{
		{database: "Login Data", tables: []browserExportTable{
			{suffix: "logins.csv", table: chromiumLoginsTable},
		}},
		// A second store, added in Chrome 89, for credentials tied to the signed-in
		// account rather than to the local profile.
		{database: "Login Data For Account", tables: []browserExportTable{
			{suffix: "logins_account.csv", table: chromiumLoginsTable},
		}},
		{database: "Web Data", tables: []browserExportTable{
			{suffix: "autofill.csv", table: chromiumAutofillTable},
			{suffix: "autofill_profiles.csv", table: chromiumAutofillProfileTable},
		}},
		{database: "formhistory.sqlite", tables: []browserExportTable{
			{suffix: "form_history.csv", table: firefoxFormHistoryTable},
		}},
	})

	if len(extra) == 0 && len(warnings) == 0 {
		return result
	}
	result.Files = append(result.Files, extra...)
	// A Firefox logins.json on its own is enough to make the module a success,
	// even when no Chromium profile had a credential store to read.
	if len(result.Files) > 0 {
		if len(warnings) == 0 {
			return result
		}
		joined := strings.Join(warnings, "; ")
		if result.Error == "" {
			result.Error = joined
		} else {
			result.Error += "; " + joined
		}
	}
	return result
}
