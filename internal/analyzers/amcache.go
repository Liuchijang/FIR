package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Liuchijang/Tyto/internal/acquisition"
	"github.com/Liuchijang/Tyto/internal/module"
	"github.com/Liuchijang/Tyto/internal/utils"
	winreg "golang.org/x/sys/windows/registry"
)

func init() { module.RegisterAnalyzer(&amcacheParser{}) }

type amcacheParser struct{}

type amcacheDataset struct {
	Filename string
	Header   []string
	Rows     [][]string
}

type amcacheResults struct {
	Datasets []amcacheDataset
}

var amcacheUnassociatedHeaders = []string{
	"ApplicationName",
	"ProgramId",
	"FileKeyLastWriteTimestamp",
	"SHA1",
	"IsOsComponent",
	"FullPath",
	"Name",
	"FileExtension",
	"LinkDate",
	"ProductName",
	"Size",
	"Version",
	"ProductVersion",
	"LongPathHash",
	"BinaryType",
	"IsPeFile",
	"BinFileVersion",
	"BinProductVersion",
	"Usn",
	"Language",
	"Description",
}

var amcacheDeviceContainerColumns = []amcacheColumn{
	amcacheKeyName("KeyName"),
	amcacheLastWrite("KeyLastWriteTimestamp"),
	amcacheJoined("Categories"),
	amcacheString("DiscoveryMethod"),
	amcacheString("FriendlyName"),
	amcacheString("Icon"),
	amcacheBool("IsActive"),
	amcacheBool("IsConnected"),
	amcacheBool("IsMachineContainer"),
	amcacheBool("IsNetworked"),
	amcacheBool("IsPaired"),
	amcacheString("Manufacturer"),
	amcacheString("ModelId"),
	amcacheString("ModelName"),
	amcacheString("ModelNumber"),
	amcacheString("PrimaryCategory"),
	amcacheDecimal("State"),
}

var amcacheDevicePnpColumns = []amcacheColumn{
	amcacheKeyName("KeyName"),
	amcacheLastWrite("KeyLastWriteTimestamp"),
	amcacheString("BusReportedDescription"),
	amcacheString("Class"),
	amcacheString("ClassGuid"),
	amcacheString("Compid"),
	amcacheString("ContainerId"),
	amcacheString("Description"),
	amcacheSHA1("DriverId"),
	amcacheString("DriverPackageStrongName"),
	amcacheString("DriverName"),
	amcacheDate("DriverVerDate"),
	amcacheString("DriverVerVersion"),
	amcacheString("Enumerator"),
	amcacheJoined("HWID"),
	amcacheString("Inf"),
	amcacheDecimal("InstallState"),
	amcacheString("Manufacturer"),
	amcacheString("MatchingId"),
	amcacheString("Model"),
	amcacheString("ParentId"),
	amcacheDecimal("ProblemCode"),
	amcacheString("Provider"),
	amcacheString("Service"),
	amcacheJoined("Stackid"),
}

var amcacheDriveBinaryColumns = []amcacheColumn{
	amcacheKeyName("KeyName"),
	amcacheLastWrite("KeyLastWriteTimestamp"),
	amcacheDate("DriverTimeStamp"),
	amcacheDate("DriverLastWriteTime"),
	amcacheString("DriverName"),
	amcacheBool("DriverInBox"),
	amcacheBool("DriverIsKernelMode"),
	amcacheBool("DriverSigned"),
	amcacheDecimal("DriverCheckSum"),
	amcacheString("DriverCompany", "DriverCompany", "Company"),
	amcacheSHA1("DriverId"),
	amcacheString("DriverPackageStrongName"),
	amcacheDecimal("DriverType"),
	amcacheString("DriverVersion"),
	amcacheDecimal("ImageSize"),
	amcacheString("Inf"),
	amcacheString("Product"),
	amcacheString("ProductVersion"),
	amcacheString("Service"),
	amcacheString("WdfVersion"),
}

var amcacheDriverPackageColumns = []amcacheColumn{
	amcacheKeyName("KeyName"),
	amcacheLastWrite("KeyLastWriteTimestamp"),
	amcacheDate("Date"),
	amcacheString("Class"),
	amcacheString("Directory"),
	amcacheBool("DriverInBox"),
	amcacheJoined("Hwids", "Hwids", "HWID"),
	amcacheString("Inf"),
	amcacheString("Provider"),
	amcacheString("SubmissionId"),
	amcacheString("SYSFILE", "SYSFILE", "SysFile"),
	amcacheString("Version"),
}

var amcacheShortcutColumns = []amcacheColumn{
	amcacheKeyName("KeyName"),
	amcacheString("LnkName", "LnkName", "ShortcutPath", "Path", "TargetPath"),
	amcacheLastWrite("KeyLastWriteTimestamp"),
}

func (c *amcacheParser) Name() string     { return "amcache_parser" }
func (c *amcacheParser) Category() string { return "execution" }
func (c *amcacheParser) Description() string {
	return "Parse Amcache"
}

func (c *amcacheParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return analyzerError(outDir, fmt.Errorf("create amcache parser output dir: %w", err))
	}

	var errs []string
	var collectedPath string

	if collected, ok := collectedAmcacheHive(req.OutputDir); ok {
		collectedPath = collected
		if results, err := parseAmcacheResultsFromHiveFile(collected); err == nil && len(results.Datasets) > 0 {
			return writeAmcacheAnalyzeResult(outDir, results)
		} else if err != nil {
			errs = append(errs, "parse collected hive: "+err.Error())
		}
	}

	if results, err := parseLiveAmcacheResults(); err == nil && len(results.Datasets) > 0 {
		return writeAmcacheAnalyzeResult(outDir, results)
	} else if err != nil {
		errs = append(errs, "parse live registry: "+err.Error())
	}

	autoCollectedHive, cleanupAutoCollect, err := collectAmcacheSourceForParser(ctx, req, outDir)
	if err == nil {
		if cleanupAutoCollect != nil {
			defer cleanupAutoCollect()
		}
		// collectAmcacheSourceForParser returns the same path already tried
		// above whenever the amcache collector already ran (its "auto-collect"
		// step is a no-op in that case) — retrying it can't produce a
		// different result, so skip straight to the fresh staged-hive attempt.
		if autoCollectedHive != "" && autoCollectedHive != collectedPath {
			if results, err := parseAmcacheResultsFromHiveFile(autoCollectedHive); err == nil && len(results.Datasets) > 0 {
				return writeAmcacheAnalyzeResult(outDir, results)
			} else if err != nil {
				errs = append(errs, "parse auto-collected hive: "+err.Error())
			}
		}
	} else {
		errs = append(errs, "auto-collect failed: "+err.Error())
	}

	hivePath, cleanup, err := stageLiveAmcacheHive(outDir)
	if err == nil {
		defer cleanup()
		if results, parseErr := parseAmcacheResultsFromHiveFile(hivePath); parseErr == nil && len(results.Datasets) > 0 {
			return writeAmcacheAnalyzeResult(outDir, results)
		} else if parseErr != nil {
			errs = append(errs, "parse staged live hive: "+parseErr.Error())
		}
	} else {
		errs = append(errs, "live staging failed: "+err.Error())
	}

	if len(errs) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: "Amcache hive is not available"}
	}
	return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("Amcache hive is not available. %s", strings.Join(errs, "; "))}
}

func writeAmcacheAnalyzeResult(outDir string, results amcacheResults) module.AnalyzeResult {
	files, err := writeAmcacheResults(outDir, results)
	if err != nil {
		return analyzerError(outDir, err)
	}
	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}

func writeAmcacheResults(outDir string, results amcacheResults) ([]module.FileInfo, error) {
	var files []module.FileInfo
	for _, dataset := range results.Datasets {
		if dataset.Rows == nil {
			continue
		}

		info, err := writeCSV(filepath.Join(outDir, dataset.Filename), dataset.Header, dataset.Rows)
		if err != nil {
			return nil, err
		}
		files = append(files, info)
	}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if len(files) == 0 {
		return nil, fmt.Errorf("no Amcache CSVs generated")
	}
	return files, nil
}

func parseLiveAmcacheResults() (amcacheResults, error) {
	root, ok, err := openRegistryKeyOptional(winreg.LOCAL_MACHINE, `AMCACHE`)
	if err != nil {
		return amcacheResults{}, fmt.Errorf("open live AMCACHE key: %w", err)
	}
	if !ok {
		return amcacheResults{}, nil
	}
	defer root.Close()

	return parseAmcacheResultsFromRoot(root)
}

func parseAmcacheResultsFromHiveFile(hivePath string) (amcacheResults, error) {
	root, err := loadRegistryAppKey(hivePath)
	if err != nil {
		return amcacheResults{}, err
	}
	defer root.Close()
	return parseAmcacheResultsFromRoot(root)
}

func parseAmcacheResultsFromRoot(root winreg.Key) (amcacheResults, error) {
	if results, matched, err := parseNewAmcacheResults(root); err != nil {
		return amcacheResults{}, err
	} else if matched {
		return results, nil
	}
	if results, matched, err := parseOldAmcacheResults(root); err != nil {
		return amcacheResults{}, err
	} else if matched {
		return results, nil
	}
	return amcacheResults{}, nil
}

// amcacheInventories drives the Root\Inventory* subkeys this parser exports. Adding
// an inventory is a table entry, not another copy of the open/parse/append block.
var amcacheInventories = []struct {
	paths    []string
	filename string
	columns  []amcacheColumn
}{
	{[]string{`Root\InventoryDeviceContainer`}, "amcache_device_containers.csv", amcacheDeviceContainerColumns},
	{[]string{`Root\InventoryDevicePnp`}, "amcache_device_pnps.csv", amcacheDevicePnpColumns},
	{[]string{`Root\InventoryDriverBinary`}, "amcache_drive_binaries.csv", amcacheDriveBinaryColumns},
	{[]string{`Root\InventoryDriverPackage`}, "amcache_driver_packages.csv", amcacheDriverPackageColumns},
	{[]string{`Root\InventoryApplicationShortcut`, `Root\InventoryShortcut`}, "amcache_shortcuts.csv", amcacheShortcutColumns},
}

func parseNewAmcacheResults(root winreg.Key) (amcacheResults, bool, error) {
	programsKey, programsOK, err := openRegistryKeyOptional(root, `Root\InventoryApplication`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryApplication: %w", err)
	}
	if programsOK {
		defer programsKey.Close()
	}

	filesKey, filesOK, err := openRegistryKeyOptional(root, `Root\InventoryApplicationFile`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryApplicationFile: %w", err)
	}
	if filesOK {
		defer filesKey.Close()
	}

	inventoryKeys := make([]winreg.Key, len(amcacheInventories))
	present := make([]bool, len(amcacheInventories))
	matched := programsOK || filesOK
	for i, inv := range amcacheInventories {
		key, ok, err := openAmcacheOptionalKey(root, inv.paths...)
		if err != nil {
			return amcacheResults{}, false, fmt.Errorf("open %s: %w", inv.paths[0], err)
		}
		if !ok {
			continue
		}
		defer key.Close()
		inventoryKeys[i], present[i] = key, true
		matched = true
	}

	if !matched {
		return amcacheResults{}, false, nil
	}

	programIDs := map[string]struct{}{}
	if programsOK {
		names, err := programsKey.ReadSubKeyNames(-1)
		if err != nil {
			return amcacheResults{}, true, fmt.Errorf("enumerate InventoryApplication: %w", err)
		}
		for _, name := range names {
			programIDs[strings.TrimSpace(name)] = struct{}{}
		}
	}

	results := amcacheResults{}
	if filesOK {
		rows, err := parseInventoryApplicationFileRows(filesKey, programIDs)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_unassociated_file_entries.csv",
			Header:   amcacheUnassociatedHeaders,
			Rows:     rows,
		})
	}

	for i, inv := range amcacheInventories {
		if !present[i] {
			continue
		}
		label := strings.TrimPrefix(inv.paths[0], `Root\`)
		rows, err := amcacheSubkeyRows(inventoryKeys[i], label, inv.columns)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: inv.filename,
			Header:   amcacheHeaders(inv.columns),
			Rows:     rows,
		})
	}

	return results, true, nil
}

func parseInventoryApplicationFileRows(filesKey winreg.Key, programIDs map[string]struct{}) ([][]string, error) {
	names, err := filesKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryApplicationFile: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(filesKey, name, winreg.READ)
		if err != nil {
			continue
		}

		programID := strings.TrimSpace(readRegistryFirstString(key, "ProgramId"))
		if _, ok := programIDs[programID]; ok {
			key.Close()
			continue
		}

		fullPath := readRegistryFirstString(key, "LowerCaseLongPath", "LongPath", "Path")
		fileName := readRegistryFirstString(key, "Name")
		if fileName == "" && fullPath != "" {
			fileName = filepath.Base(fullPath)
		}
		fileExt := readRegistryFirstString(key, "FileExtension")
		if fileExt == "" && fileName != "" {
			fileExt = strings.ToLower(filepath.Ext(fileName))
		}

		rows = append(rows, []string{
			"Unassociated",
			programID,
			registryKeyLastWriteString(key),
			normalizeAmcacheSHA1(readRegistryFirstString(key, "FileId", "SHA1")),
			readRegistryFirstBoolStringDefault(key, "False", "IsOsComponent"),
			fullPath,
			fileName,
			fileExt,
			normalizeRegistryDateString(readRegistryFirstString(key, "LinkDate")),
			readRegistryFirstString(key, "ProductName"),
			readRegistryFirstDecimalString(key, "Size"),
			readRegistryFirstString(key, "Version"),
			readRegistryFirstString(key, "ProductVersion", "Version"),
			readRegistryFirstString(key, "LongPathHash"),
			readRegistryFirstString(key, "BinaryType"),
			readRegistryFirstBoolStringDefault(key, "False", "IsPeFile"),
			readRegistryFirstString(key, "BinFileVersion", "FileVersion"),
			readRegistryFirstString(key, "BinProductVersion", "ProductVersion"),
			readRegistryFirstDecimalString(key, "Usn"),
			readRegistryFirstString(key, "Language"),
			readRegistryFirstString(key, "Description"),
		})
		key.Close()
	}

	return rows, nil
}

// amcacheField pulls one CSV column out of an inventory subkey.
type amcacheField func(key winreg.Key, keyName string) string

// amcacheColumn keeps a column's header next to the value that fills it. The two
// used to be a package-level header slice and a positional row literal three
// hundred lines apart, so adding a column to one and not the other silently
// shifted every value after it one column left.
type amcacheColumn struct {
	header  string
	extract amcacheField
}

// amcacheValueNames defaults a column's registry value names to its header, which
// is what all but four of them use.
func amcacheValueNames(header string, names []string) []string {
	if len(names) == 0 {
		return []string{header}
	}
	return names
}

func amcacheKeyName(header string) amcacheColumn {
	return amcacheColumn{header, func(_ winreg.Key, keyName string) string { return keyName }}
}

func amcacheLastWrite(header string) amcacheColumn {
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return registryKeyLastWriteString(key)
	}}
}

func amcacheString(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return readRegistryFirstString(key, names...)
	}}
}

func amcacheJoined(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return readRegistryFirstJoinedString(key, names...)
	}}
}

func amcacheDecimal(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return readRegistryFirstDecimalString(key, names...)
	}}
}

// amcacheBool defaults to "False" rather than "" so a missing flag reads as the
// flag being off, which is what Amcache means by omitting it.
func amcacheBool(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return readRegistryFirstBoolStringDefault(key, "False", names...)
	}}
}

func amcacheDate(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return normalizeRegistryDateString(readRegistryFirstString(key, names...))
	}}
}

func amcacheSHA1(header string, names ...string) amcacheColumn {
	names = amcacheValueNames(header, names)
	return amcacheColumn{header, func(key winreg.Key, _ string) string {
		return normalizeAmcacheSHA1(readRegistryFirstString(key, names...))
	}}
}

func amcacheHeaders(columns []amcacheColumn) []string {
	headers := make([]string, len(columns))
	for i, column := range columns {
		headers[i] = column.header
	}
	return headers
}

// amcacheSubkeyRows emits one row per subkey of root. Every Root\Inventory*
// export has this shape; only the columns differ. A subkey that will not open is
// skipped rather than failing the inventory, because one unreadable device entry
// should not cost the other few thousand.
func amcacheSubkeyRows(root winreg.Key, label string, columns []amcacheColumn) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate %s: %w", label, err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		row := make([]string, len(columns))
		for i, column := range columns {
			row[i] = column.extract(key, name)
		}
		rows = append(rows, row)
		key.Close()
	}
	return rows, nil
}

func parseOldAmcacheResults(root winreg.Key) (amcacheResults, bool, error) {
	programsKey, programsOK, err := openRegistryKeyOptional(root, `Root\Programs`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open Programs: %w", err)
	}
	if programsOK {
		defer programsKey.Close()
	}

	filesKey, filesOK, err := openRegistryKeyOptional(root, `Root\File`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open File: %w", err)
	}
	if filesOK {
		defer filesKey.Close()
	}
	if !programsOK && !filesOK {
		return amcacheResults{}, false, nil
	}

	programIDs := map[string]struct{}{}
	if programsOK {
		names, err := programsKey.ReadSubKeyNames(-1)
		if err != nil {
			return amcacheResults{}, false, fmt.Errorf("enumerate Programs: %w", err)
		}
		for _, name := range names {
			programIDs[strings.TrimSpace(name)] = struct{}{}
		}
	}

	rows := make([][]string, 0, 512)
	if filesOK {
		if err := walkAmcacheFileKeys(filesKey, `Root\File`, func(_ string, entryKey string, key winreg.Key) error {
			values := registryValueNames(key)
			if !values["15"] && !values["101"] {
				return nil
			}

			programID := strings.TrimSpace(readRegistryFirstString(key, "100"))
			if _, ok := programIDs[programID]; ok {
				return nil
			}

			fullPath := readRegistryFirstString(key, "15")
			fileName := filepath.Base(fullPath)
			rows = append(rows, []string{
				"Unassociated",
				programID,
				registryKeyLastWriteString(key),
				normalizeAmcacheSHA1(readRegistryFirstString(key, "101")),
				"False",
				fullPath,
				fileName,
				strings.ToLower(filepath.Ext(fileName)),
				"",
				readRegistryFirstString(key, "0"),
				readRegistryFirstDecimalString(key, "6"),
				readRegistryFirstString(key, "d"),
				readRegistryFirstString(key, "d"),
				"",
				"",
				"False",
				readRegistryFirstString(key, "d"),
				"",
				"",
				readRegistryFirstDecimalString(key, "3"),
				readRegistryFirstString(key, "c"),
			})
			return nil
		}); err != nil {
			return amcacheResults{}, true, err
		}
	}

	return amcacheResults{
		Datasets: []amcacheDataset{
			{
				Filename: "amcache_unassociated_file_entries.csv",
				Header:   amcacheUnassociatedHeaders,
				Rows:     rows,
			},
		},
	}, true, nil
}

func walkAmcacheFileKeys(key winreg.Key, currentPath string, visit func(keyPath, entryKey string, key winreg.Key) error) error {
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return fmt.Errorf("enumerate %s: %w", currentPath, err)
	}
	for _, name := range names {
		subKey, err := winreg.OpenKey(key, name, winreg.READ)
		if err != nil {
			continue
		}
		nextPath := currentPath + `\` + name
		if err := visit(nextPath, name, subKey); err != nil {
			subKey.Close()
			return err
		}
		if err := walkAmcacheFileKeys(subKey, nextPath, visit); err != nil {
			subKey.Close()
			return err
		}
		subKey.Close()
	}
	return nil
}

func openAmcacheOptionalKey(root winreg.Key, paths ...string) (winreg.Key, bool, error) {
	for _, path := range paths {
		key, ok, err := openRegistryKeyOptional(root, path)
		if err != nil {
			return 0, false, err
		}
		if ok {
			return key, true, nil
		}
	}
	return 0, false, nil
}

func readRegistryFirstDecimalString(key winreg.Key, names ...string) string {
	if value, ok := readRegistryFirstUint64(key, names...); ok {
		return strconv.FormatUint(value, 10)
	}
	return readRegistryFirstString(key, names...)
}

func readRegistryFirstBoolString(key winreg.Key, names ...string) string {
	for _, name := range names {
		if value, ok := readRegistryIntegerValue(key, name); ok {
			return boolString(value != 0)
		}
		if value, ok := readRegistryStringValue(key, name); ok {
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "1", "true", "yes":
				return "True"
			case "0", "false", "no":
				return "False"
			default:
				return value
			}
		}
	}
	return ""
}

func readRegistryFirstBoolStringDefault(key winreg.Key, defaultValue string, names ...string) string {
	value := readRegistryFirstBoolString(key, names...)
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func readRegistryFirstJoinedString(key winreg.Key, names ...string) string {
	for _, name := range names {
		if value, _, err := key.GetStringsValue(name); err == nil {
			return strings.Join(value, ",")
		}
		if value, ok := readRegistryStringValue(key, name); ok {
			return value
		}
	}
	return ""
}

// Amcache pads FileId/DriverId with four leading zeros before the 40-char SHA-1.
// Only that pad may be dropped — trimming every leading zero also eats the hash's
// own, producing a wrong hash for roughly one entry in sixteen.
func normalizeAmcacheSHA1(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if strings.Trim(value, "0") == "" {
		return ""
	}
	if len(value) == 44 {
		return value[4:]
	}
	return strings.TrimPrefix(value, "0000")
}

// stageLiveAmcacheHive puts a mountable copy of the live Amcache.hve under
// workDir, because RegLoadAppKeyW needs a file it can open for write to replay
// the hive's pending transactions.
//
// workDir is the analyzer's own output directory rather than the machine's
// %TEMP%: staging here would otherwise write the hive and both of its
// transaction logs onto the volume being investigated, and a run that is killed
// mid-parse would leave them there.
func stageLiveAmcacheHive(workDir string) (string, func(), error) {
	src := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	if _, err := os.Stat(src); err != nil {
		return "", nil, err
	}

	tempDir, err := os.MkdirTemp(workDir, "amcache-stage-")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() { _ = os.RemoveAll(tempDir) }
	dst := filepath.Join(tempDir, "Amcache.hve")

	// A raw file copy carries over whatever "dirty" (pending transaction) state
	// the live hive currently has, so RegLoadAppKeyW needs the matching
	// .LOG1/.LOG2 files next to it to replay and mount — without them it fails
	// with "the configuration registry database is corrupt" even though the
	// hive file itself copied fine. Stage them alongside on a best-effort
	// basis; a clean hive with no pending transactions doesn't need them.
	stageLogs := func(copyOne func(logSrc, logDst string) error) {
		for _, suffix := range []string{".LOG1", ".LOG2"} {
			_ = copyOne(src+suffix, dst+suffix)
		}
	}

	var errs []string
	if err := utils.SaveRegistryHive(winreg.LOCAL_MACHINE, "AMCACHE", dst); err == nil {
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("save mounted AMCACHE hive: %v", err))
	}
	if _, err := utils.SafeCopyFile(src, dst); err == nil {
		stageLogs(func(logSrc, logDst string) error {
			_, err := utils.SafeCopyFile(logSrc, logDst)
			return err
		})
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("copy file: %v", err))
	}
	if _, err := utils.SafeCopyFileBackup(src, dst); err == nil {
		stageLogs(func(logSrc, logDst string) error {
			_, err := utils.SafeCopyFileBackup(logSrc, logDst)
			return err
		})
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("copy file with backup semantics: %v", err))
	}

	vol, err := acquisition.OpenRawVolume("C")
	if err == nil {
		defer vol.Close()
		if volData, volErr := vol.GetNTFSVolumeData(); volErr == nil {
			if _, copyErr := acquisition.CopyFileFromRawPath(vol, volData, src, dst); copyErr == nil {
				stageLogs(func(logSrc, logDst string) error {
					_, err := acquisition.CopyFileFromRawPath(vol, volData, logSrc, logDst)
					return err
				})
				return dst, cleanup, nil
			} else {
				errs = append(errs, fmt.Sprintf("copy via raw volume: %v", copyErr))
			}
		} else {
			errs = append(errs, fmt.Sprintf("read NTFS volume data: %v", volErr))
		}
	} else {
		errs = append(errs, fmt.Sprintf("open raw volume: %v", err))
	}

	cleanup()
	return "", nil, fmt.Errorf("%s", strings.Join(errs, "; "))
}

func collectedAmcacheHive(outputDir string) (string, bool) {
	if dir, ok := existingModuleDir(outputDir, "amcache"); ok {
		collected := filepath.Join(dir, "Amcache.hve")
		if _, err := os.Stat(collected); err == nil {
			return collected, true
		}
	}
	return "", false
}

func collectAmcacheSource(ctx context.Context, outputDir string) error {
	mod, err := module.Get("amcache")
	if err != nil {
		return err
	}
	_, err = mod.Collect(ctx, outputDir)
	return err
}

func collectAmcacheSourceForParser(ctx context.Context, req module.AnalyzeRequest, workDir string) (string, func(), error) {
	if req.IsSelected("amcache") {
		if collected, ok := collectedAmcacheHive(req.OutputDir); ok {
			return collected, nil, nil
		}
		return "", nil, fmt.Errorf("amcache collector was selected but Amcache.hve was not found in run output")
	}

	// Under the analyzer's own directory, not %TEMP%: this runs the whole amcache
	// collector, so the destination receives a full copy of the hive on the
	// volume under investigation if it points at the subject's temp directory.
	tempDir, err := os.MkdirTemp(workDir, "amcache-collect-")
	if err != nil {
		return "", nil, fmt.Errorf("create work dir for hidden amcache collection: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }

	if err := collectAmcacheSource(ctx, tempDir); err != nil {
		cleanup()
		return "", nil, err
	}
	if collected, ok := collectedAmcacheHive(tempDir); ok {
		return collected, cleanup, nil
	}

	cleanup()
	return "", nil, fmt.Errorf("hidden amcache collection completed but Amcache.hve was not found")
}
