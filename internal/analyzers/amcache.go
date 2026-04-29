package analyzers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
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

var amcacheDeviceContainerHeaders = []string{
	"KeyName",
	"KeyLastWriteTimestamp",
	"Categories",
	"DiscoveryMethod",
	"FriendlyName",
	"Icon",
	"IsActive",
	"IsConnected",
	"IsMachineContainer",
	"IsNetworked",
	"IsPaired",
	"Manufacturer",
	"ModelId",
	"ModelName",
	"ModelNumber",
	"PrimaryCategory",
	"State",
}

var amcacheDevicePnpHeaders = []string{
	"KeyName",
	"KeyLastWriteTimestamp",
	"BusReportedDescription",
	"Class",
	"ClassGuid",
	"Compid",
	"ContainerId",
	"Description",
	"DriverId",
	"DriverPackageStrongName",
	"DriverName",
	"DriverVerDate",
	"DriverVerVersion",
	"Enumerator",
	"HWID",
	"Inf",
	"InstallState",
	"Manufacturer",
	"MatchingId",
	"Model",
	"ParentId",
	"ProblemCode",
	"Provider",
	"Service",
	"Stackid",
}

var amcacheDriveBinaryHeaders = []string{
	"KeyName",
	"KeyLastWriteTimestamp",
	"DriverTimeStamp",
	"DriverLastWriteTime",
	"DriverName",
	"DriverInBox",
	"DriverIsKernelMode",
	"DriverSigned",
	"DriverCheckSum",
	"DriverCompany",
	"DriverId",
	"DriverPackageStrongName",
	"DriverType",
	"DriverVersion",
	"ImageSize",
	"Inf",
	"Product",
	"ProductVersion",
	"Service",
	"WdfVersion",
}

var amcacheDriverPackageHeaders = []string{
	"KeyName",
	"KeyLastWriteTimestamp",
	"Date",
	"Class",
	"Directory",
	"DriverInBox",
	"Hwids",
	"Inf",
	"Provider",
	"SubmissionId",
	"SYSFILE",
	"Version",
}

var amcacheShortcutHeaders = []string{
	"KeyName",
	"LnkName",
	"KeyLastWriteTimestamp",
}

func (c *amcacheParser) Name() string     { return "amcache_parser" }
func (c *amcacheParser) Category() string { return "execution" }
func (c *amcacheParser) Description() string {
	return "Parse Amcache"
}

func (c *amcacheParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir := req.AnalyzerDir
	if outDir == "" {
		outDir = filepath.Join(req.OutputDir, "Analyzer", c.Name())
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create amcache parser output dir: %w", err).Error()}
	}

	var errs []string

	if collected, ok := collectedAmcacheHive(req.OutputDir); ok {
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

	autoCollectedHive, cleanupAutoCollect, err := collectAmcacheSourceForParser(ctx, req)
	if err == nil {
		if cleanupAutoCollect != nil {
			defer cleanupAutoCollect()
		}
		if autoCollectedHive != "" {
			if results, err := parseAmcacheResultsFromHiveFile(autoCollectedHive); err == nil && len(results.Datasets) > 0 {
				return writeAmcacheAnalyzeResult(outDir, results)
			} else if err != nil {
				errs = append(errs, "parse auto-collected hive: "+err.Error())
			}
		}
	} else {
		errs = append(errs, "auto-collect failed: "+err.Error())
	}

	hivePath, cleanup, err := stageLiveAmcacheHive()
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
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: files, OutputPath: outDir}
}

func writeAmcacheResults(outDir string, results amcacheResults) ([]module.FileInfo, error) {
	var files []module.FileInfo
	for _, dataset := range results.Datasets {
		if dataset.Rows == nil {
			continue
		}

		outCSV := filepath.Join(outDir, dataset.Filename)
		if err := writeCSVFile(outCSV, dataset.Header, dataset.Rows); err != nil {
			return nil, err
		}
		info, err := utils.FileInfoFromPath(outCSV)
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

	deviceContainersKey, deviceContainersOK, err := openRegistryKeyOptional(root, `Root\InventoryDeviceContainer`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryDeviceContainer: %w", err)
	}
	if deviceContainersOK {
		defer deviceContainersKey.Close()
	}

	devicePnpsKey, devicePnpsOK, err := openRegistryKeyOptional(root, `Root\InventoryDevicePnp`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryDevicePnp: %w", err)
	}
	if devicePnpsOK {
		defer devicePnpsKey.Close()
	}

	driveBinariesKey, driveBinariesOK, err := openRegistryKeyOptional(root, `Root\InventoryDriverBinary`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryDriverBinary: %w", err)
	}
	if driveBinariesOK {
		defer driveBinariesKey.Close()
	}

	driverPackagesKey, driverPackagesOK, err := openRegistryKeyOptional(root, `Root\InventoryDriverPackage`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryDriverPackage: %w", err)
	}
	if driverPackagesOK {
		defer driverPackagesKey.Close()
	}

	shortcutsKey, shortcutsOK, err := openAmcacheOptionalKey(root, `Root\InventoryApplicationShortcut`, `Root\InventoryShortcut`)
	if err != nil {
		return amcacheResults{}, false, fmt.Errorf("open InventoryApplicationShortcut: %w", err)
	}
	if shortcutsOK {
		defer shortcutsKey.Close()
	}

	matched := programsOK || filesOK || deviceContainersOK || devicePnpsOK || driveBinariesOK || driverPackagesOK || shortcutsOK
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
	if deviceContainersOK {
		rows, err := parseInventoryDeviceContainerRows(deviceContainersKey)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_device_containers.csv",
			Header:   amcacheDeviceContainerHeaders,
			Rows:     rows,
		})
	}
	if devicePnpsOK {
		rows, err := parseInventoryDevicePnpRows(devicePnpsKey)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_device_pnps.csv",
			Header:   amcacheDevicePnpHeaders,
			Rows:     rows,
		})
	}
	if driveBinariesOK {
		rows, err := parseInventoryDriverBinaryRows(driveBinariesKey)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_drive_binaries.csv",
			Header:   amcacheDriveBinaryHeaders,
			Rows:     rows,
		})
	}
	if driverPackagesOK {
		rows, err := parseInventoryDriverPackageRows(driverPackagesKey)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_driver_packages.csv",
			Header:   amcacheDriverPackageHeaders,
			Rows:     rows,
		})
	}
	if shortcutsOK {
		rows, err := parseInventoryShortcutRows(shortcutsKey)
		if err != nil {
			return amcacheResults{}, true, err
		}
		results.Datasets = append(results.Datasets, amcacheDataset{
			Filename: "amcache_shortcuts.csv",
			Header:   amcacheShortcutHeaders,
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

func parseInventoryDeviceContainerRows(root winreg.Key) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryDeviceContainer: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		rows = append(rows, []string{
			name,
			registryKeyLastWriteString(key),
			readRegistryFirstJoinedString(key, "Categories"),
			readRegistryFirstString(key, "DiscoveryMethod"),
			readRegistryFirstString(key, "FriendlyName"),
			readRegistryFirstString(key, "Icon"),
			readRegistryFirstBoolStringDefault(key, "False", "IsActive"),
			readRegistryFirstBoolStringDefault(key, "False", "IsConnected"),
			readRegistryFirstBoolStringDefault(key, "False", "IsMachineContainer"),
			readRegistryFirstBoolStringDefault(key, "False", "IsNetworked"),
			readRegistryFirstBoolStringDefault(key, "False", "IsPaired"),
			readRegistryFirstString(key, "Manufacturer"),
			readRegistryFirstString(key, "ModelId"),
			readRegistryFirstString(key, "ModelName"),
			readRegistryFirstString(key, "ModelNumber"),
			readRegistryFirstString(key, "PrimaryCategory"),
			readRegistryFirstDecimalString(key, "State"),
		})
		key.Close()
	}
	return rows, nil
}

func parseInventoryDevicePnpRows(root winreg.Key) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryDevicePnp: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		rows = append(rows, []string{
			name,
			registryKeyLastWriteString(key),
			readRegistryFirstString(key, "BusReportedDescription"),
			readRegistryFirstString(key, "Class"),
			readRegistryFirstString(key, "ClassGuid"),
			readRegistryFirstString(key, "Compid"),
			readRegistryFirstString(key, "ContainerId"),
			readRegistryFirstString(key, "Description"),
			normalizeAmcacheSHA1(readRegistryFirstString(key, "DriverId")),
			readRegistryFirstString(key, "DriverPackageStrongName"),
			readRegistryFirstString(key, "DriverName"),
			normalizeRegistryDateString(readRegistryFirstString(key, "DriverVerDate")),
			readRegistryFirstString(key, "DriverVerVersion"),
			readRegistryFirstString(key, "Enumerator"),
			readRegistryFirstJoinedString(key, "HWID"),
			readRegistryFirstString(key, "Inf"),
			readRegistryFirstDecimalString(key, "InstallState"),
			readRegistryFirstString(key, "Manufacturer"),
			readRegistryFirstString(key, "MatchingId"),
			readRegistryFirstString(key, "Model"),
			readRegistryFirstString(key, "ParentId"),
			readRegistryFirstDecimalString(key, "ProblemCode"),
			readRegistryFirstString(key, "Provider"),
			readRegistryFirstString(key, "Service"),
			readRegistryFirstJoinedString(key, "Stackid"),
		})
		key.Close()
	}
	return rows, nil
}

func parseInventoryDriverBinaryRows(root winreg.Key) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryDriverBinary: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		rows = append(rows, []string{
			name,
			registryKeyLastWriteString(key),
			normalizeRegistryDateString(readRegistryFirstString(key, "DriverTimeStamp")),
			normalizeRegistryDateString(readRegistryFirstString(key, "DriverLastWriteTime")),
			readRegistryFirstString(key, "DriverName"),
			readRegistryFirstBoolStringDefault(key, "False", "DriverInBox"),
			readRegistryFirstBoolStringDefault(key, "False", "DriverIsKernelMode"),
			readRegistryFirstBoolStringDefault(key, "False", "DriverSigned"),
			readRegistryFirstDecimalString(key, "DriverCheckSum"),
			readRegistryFirstString(key, "DriverCompany", "Company"),
			normalizeAmcacheSHA1(readRegistryFirstString(key, "DriverId")),
			readRegistryFirstString(key, "DriverPackageStrongName"),
			readRegistryFirstDecimalString(key, "DriverType"),
			readRegistryFirstString(key, "DriverVersion"),
			readRegistryFirstDecimalString(key, "ImageSize"),
			readRegistryFirstString(key, "Inf"),
			readRegistryFirstString(key, "Product"),
			readRegistryFirstString(key, "ProductVersion"),
			readRegistryFirstString(key, "Service"),
			readRegistryFirstString(key, "WdfVersion"),
		})
		key.Close()
	}
	return rows, nil
}

func parseInventoryDriverPackageRows(root winreg.Key) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryDriverPackage: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		rows = append(rows, []string{
			name,
			registryKeyLastWriteString(key),
			normalizeRegistryDateString(readRegistryFirstString(key, "Date")),
			readRegistryFirstString(key, "Class"),
			readRegistryFirstString(key, "Directory"),
			readRegistryFirstBoolStringDefault(key, "False", "DriverInBox"),
			readRegistryFirstJoinedString(key, "Hwids", "HWID"),
			readRegistryFirstString(key, "Inf"),
			readRegistryFirstString(key, "Provider"),
			readRegistryFirstString(key, "SubmissionId"),
			readRegistryFirstString(key, "SYSFILE", "SysFile"),
			readRegistryFirstString(key, "Version"),
		})
		key.Close()
	}
	return rows, nil
}

func parseInventoryShortcutRows(root winreg.Key) ([][]string, error) {
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate InventoryApplicationShortcut: %w", err)
	}

	rows := make([][]string, 0, len(names))
	for _, name := range names {
		key, err := winreg.OpenKey(root, name, winreg.READ)
		if err != nil {
			continue
		}
		rows = append(rows, []string{
			name,
			readRegistryFirstString(key, "LnkName", "ShortcutPath", "Path", "TargetPath"),
			registryKeyLastWriteString(key),
		})
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

func normalizeAmcacheSHA1(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimLeft(value, "0")
	return value
}

func stageLiveAmcacheHive() (string, func(), error) {
	src := filepath.Join(os.Getenv("SystemRoot"), "AppCompat", "Programs", "Amcache.hve")
	if _, err := os.Stat(src); err != nil {
		return "", nil, err
	}

	tempDir, err := os.MkdirTemp("", "fir-amcache-")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() { _ = os.RemoveAll(tempDir) }
	dst := filepath.Join(tempDir, "Amcache.hve")

	var errs []string
	if err := utils.SaveRegistryHive(winreg.LOCAL_MACHINE, "AMCACHE", dst); err == nil {
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("save mounted AMCACHE hive: %v", err))
	}
	if _, err := utils.SafeCopyFile(src, dst); err == nil {
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("copy file: %v", err))
	}
	if _, err := utils.SafeCopyFileBackup(src, dst); err == nil {
		return dst, cleanup, nil
	} else {
		errs = append(errs, fmt.Sprintf("copy file with backup semantics: %v", err))
	}

	vol, err := acquisition.OpenRawVolume("C")
	if err == nil {
		defer vol.Close()
		if volData, volErr := vol.GetNTFSVolumeData(); volErr == nil {
			if _, copyErr := acquisition.CopyFileFromRawPath(vol, volData, src, dst); copyErr == nil {
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

func collectAmcacheSourceForParser(ctx context.Context, req module.AnalyzeRequest) (string, func(), error) {
	if req.IsSelected("amcache") {
		if collected, ok := collectedAmcacheHive(req.OutputDir); ok {
			return collected, nil, nil
		}
		return "", nil, fmt.Errorf("amcache collector was selected but Amcache.hve was not found in run output")
	}

	tempDir, err := os.MkdirTemp("", "fir-amcache-parser-source-")
	if err != nil {
		return "", nil, fmt.Errorf("create temp dir for hidden amcache collection: %w", err)
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
