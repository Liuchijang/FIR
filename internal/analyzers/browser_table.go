package analyzers

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// A browser's SQLite schema changes with every few Chrome releases: the History
// downloads table alone has seven distinct column sets in the wild, logins has
// three, DIPS four. The usual answer is a table of queries keyed by the database
// version, which has to be extended for each new release and silently falls back
// to the oldest query — dropping columns — for a version it has not seen.
//
// browserTable takes the other route: ask the schema which of the wanted columns
// it has, select those, and leave the rest blank. The CSV header stays fixed
// whatever Chrome build produced the artifact, there is no version table to
// maintain, and a schema newer than this code still yields everything it holds.
type browserTable struct {
	// name is a constant in this package, never caller input — it is
	// interpolated into SQL, which would otherwise be an injection point.
	name    string
	columns []browserColumn
	orderBy string
}

// browserColumn is one CSV column. Several may read the same SQLite column: that
// is how a raw enum value and its decoded name end up side by side, the way
// srum_parser keeps AppId next to AppIdResolved.
type browserColumn struct {
	source string
	header string
	render func(value any) string
}

func rawColumn(source string) browserColumn {
	return browserColumn{source: source, header: source, render: renderBrowserValue}
}

func namedColumn(source, header string, render func(any) string) browserColumn {
	return browserColumn{source: source, header: header, render: render}
}

// chromiumTimeColumn renders a Chromium timestamp: microseconds since 1601.
func chromiumTimeColumn(source, header string) browserColumn {
	return namedColumn(source, header, func(value any) string {
		return chromiumTimeString(browserInt(value))
	})
}

// unixSecondsColumn renders a plain Unix-epoch seconds value, which is what the
// Media History database stores.
func unixSecondsColumn(source, header string) browserColumn {
	return namedColumn(source, header, func(value any) string {
		seconds := browserInt(value)
		if seconds <= 0 {
			return ""
		}
		return formatUnixMicro(seconds*1_000_000, "")
	})
}

// boolColumn renders SQLite's 0/1 integers as booleans.
func boolColumn(source, header string) browserColumn {
	return namedColumn(source, header, func(value any) string {
		if value == nil {
			return ""
		}
		return strconv.FormatBool(browserInt(value) != 0)
	})
}

// enumColumn decodes a numeric code. The raw value keeps its own column, so a
// code this table does not know is still visible and verifiable.
func enumColumn(source, header string, names map[int64]string) browserColumn {
	return namedColumn(source, header, func(value any) string {
		if value == nil {
			return ""
		}
		code := browserInt(value)
		if name, ok := names[code]; ok {
			return name
		}
		return "unknown(" + strconv.FormatInt(code, 10) + ")"
	})
}

func (t browserTable) headers() []string {
	out := make([]string, 0, len(t.columns))
	for _, column := range t.columns {
		out = append(out, column.header)
	}
	return out
}

// stream emits one []string per row, aligned to headers(). It returns false when
// the table is not in this database at all, which is the normal case for an
// artifact a given Chrome version does not maintain.
func (t browserTable) stream(ctx context.Context, db *sql.DB, emit func([]string) error) (bool, error) {
	present, err := browserTableColumns(ctx, db, t.name)
	if err != nil || len(present) == 0 {
		return false, err
	}

	// One SELECT entry per distinct source column, remembering where each landed
	// so several output columns can read the same value.
	var selected []string
	position := make(map[string]int, len(t.columns))
	for _, column := range t.columns {
		if !present[column.source] {
			continue
		}
		if _, ok := position[column.source]; ok {
			continue
		}
		position[column.source] = len(selected)
		selected = append(selected, `"`+column.source+`"`)
	}
	if len(selected) == 0 {
		return false, fmt.Errorf("table %s has none of the expected columns", t.name)
	}

	query := "SELECT " + strings.Join(selected, ", ") + ` FROM "` + t.name + `"`
	if t.orderBy != "" && present[t.orderBy] {
		query += ` ORDER BY "` + t.orderBy + `"`
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return false, fmt.Errorf("query %s: %w", t.name, err)
	}
	defer rows.Close()

	values := make([]any, len(selected))
	scan := make([]any, len(selected))
	for i := range values {
		scan[i] = &values[i]
	}

	record := make([]string, len(t.columns))
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return true, err
		}
		if err := rows.Scan(scan...); err != nil {
			// One unreadable row should not cost the rest of the table.
			continue
		}
		for i, column := range t.columns {
			idx, ok := position[column.source]
			if !ok {
				record[i] = ""
				continue
			}
			record[i] = column.render(values[idx])
		}
		if err := emit(record); err != nil {
			return true, err
		}
	}
	return true, rows.Err()
}

// browserTableColumns reports the columns a table actually has, or nothing at
// all when the table is absent.
func browserTableColumns(ctx context.Context, db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, fmt.Errorf("read schema of %s: %w", table, err)
	}
	defer rows.Close()

	present := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		present[name] = true
	}
	return present, rows.Err()
}

// browserInt coerces a SQLite value to an integer. SQLite is dynamically typed
// and the same column can come back as an integer on one profile and as text on
// another, so the conversion has to be tolerant rather than assume a type.
func browserInt(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	case []byte:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(string(typed)), 10, 64)
		return parsed
	default:
		return 0
	}
}

// browserEncryptionState names the wrapper around a stored secret.
//
// Tyto does not decrypt browser secrets, so the column holding one is hex and
// nothing more. This says which scheme produced it, which is the part that
// decides what an analyst can do next:
//
//   - v10/v11 are AES-256-GCM under a key in Local State, itself wrapped with
//     DPAPI. Recoverable offline given the profile and the user's DPAPI master
//     key, which is why the collector keeps Local State alongside.
//   - v20 is App-Bound Encryption, added in Chrome 127. The key is held by an
//     elevated system service tied to the machine, so the value is effectively
//     unrecoverable away from the original host — worth knowing before spending
//     time on it.
//   - Anything else with content is a pre-Chrome-80 profile, or Linux with no
//     keyring, where the value was never encrypted at all.
func browserEncryptionState(value any) string {
	raw, ok := value.([]byte)
	if !ok {
		if text, isText := value.(string); isText && text != "" {
			return "Plaintext"
		}
		return ""
	}
	if len(raw) == 0 {
		return ""
	}
	if len(raw) >= 3 {
		switch string(raw[:3]) {
		case "v10":
			return "Encrypted (v10, AES-GCM via DPAPI key)"
		case "v11":
			return "Encrypted (v11, AES-GCM via DPAPI key)"
		case "v20":
			return "Encrypted (v20, App-Bound; host-locked)"
		}
	}
	return "Plaintext"
}

// encryptionStateColumn reports what wraps a secret, beside the secret itself.
func encryptionStateColumn(source, header string) browserColumn {
	return namedColumn(source, header, browserEncryptionState)
}

// renderBrowserValue formats a value with no interpretation attached. A BLOB is
// hex-encoded rather than dropped: an encrypted cookie value is evidence even
// while it stays encrypted, and hex is the form another tool can take back.
func renderBrowserValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return hex.EncodeToString(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
