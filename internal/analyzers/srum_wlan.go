package analyzers

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Liuchijang/Tyto/internal/module"
	winreg "golang.org/x/sys/windows/registry"
)

// wlanInterfacesKey is where WlanSvc records one subkey per wireless adapter,
// each holding the profiles that adapter has connected through.
const wlanInterfacesKey = `Microsoft\WlanSvc\Interfaces`

// srumWLANProfiles maps a SRUM L2ProfileId to the network it names.
//
// SRUM's network tables identify a wireless network only by that integer, which
// is WlanSvc's ProfileIndex. The SSID lives in the SOFTWARE hive, so resolving
// "which network was this machine on" needs both artifacts — the same shape as
// usnjrnl_parser joining against $MFT.
type srumWLANProfiles map[int32]string

// loadSRUMWLANProfiles reads the profile index from the SOFTWARE hive collected
// by this run, falling back to the live hive.
//
// Failure is not an error: the SSID is enrichment, and a run without the
// registry collector still produces complete SRUM tables with the raw
// L2ProfileId in them. That is also why an offline run simply returns nothing
// here rather than reporting a missing artifact.
func loadSRUMWLANProfiles(req module.AnalyzeRequest) srumWLANProfiles {
	dir, live, err := resolveArtifactSource(req, "registry")
	if err != nil {
		return nil
	}
	if live {
		root, ok, err := openLiveKey(winreg.LOCAL_MACHINE, `SOFTWARE\`+wlanInterfacesKey)
		if err != nil || !ok {
			return nil
		}
		defer root.Close()
		return readWLANProfiles(root, "")
	}

	hive := filepath.Join(dir, "SOFTWARE")
	if _, err := os.Stat(hive); err != nil {
		return nil
	}
	root, err := openCollectedHive(hive)
	if err != nil {
		return nil
	}
	defer root.Close()
	return readWLANProfiles(root, wlanInterfacesKey)
}

func readWLANProfiles(root registryKey, interfacesPath string) srumWLANProfiles {
	interfaces, ok, err := root.OpenSubkey(interfacesPath)
	if err != nil || !ok {
		return nil
	}
	defer interfaces.Close()

	adapters, err := interfaces.SubkeyNames()
	if err != nil {
		return nil
	}

	profiles := make(srumWLANProfiles)
	for _, adapter := range adapters {
		collectWLANAdapterProfiles(interfaces, adapter, profiles)
	}
	return profiles
}

func collectWLANAdapterProfiles(interfaces registryKey, adapter string, profiles srumWLANProfiles) {
	profilesKey, ok, err := interfaces.OpenSubkey(adapter + `\Profiles`)
	if err != nil || !ok {
		return
	}
	defer profilesKey.Close()

	names, err := profilesKey.SubkeyNames()
	if err != nil {
		return
	}
	for _, name := range names {
		profileKey, ok, err := profilesKey.OpenSubkey(name)
		if err != nil || !ok {
			continue
		}
		index, hasIndex := readRegistryIntegerValue(profileKey, "ProfileIndex")
		ssid := readWLANProfileName(profileKey)
		profileKey.Close()

		if hasIndex && ssid != "" {
			profiles[int32(index)] = ssid
		}
	}
}

// readWLANProfileName prefers MetaData\Description, which is the SSID as the
// user sees it. Channel Hints is the fallback because older profiles have no
// Description: its payload is a 4-byte length followed by the SSID bytes.
func readWLANProfileName(profileKey registryKey) string {
	metadata, ok, err := profileKey.OpenSubkey("MetaData")
	if err != nil || !ok {
		return ""
	}
	defer metadata.Close()

	if description := readRegistryFirstString(metadata, "Description"); description != "" {
		return description
	}
	for _, name := range []string{"Channel Hints", "Band Channel Hints"} {
		if hint, ok := readRegistryBinaryValue(metadata, name); ok {
			if ssid := parseChannelHintSSID(hint); ssid != "" {
				return ssid
			}
		}
	}
	return ""
}

func parseChannelHintSSID(hint []byte) string {
	if len(hint) < 4 {
		return ""
	}
	length := int(binary.LittleEndian.Uint32(hint[0:4]))
	if length <= 0 || 4+length > len(hint) {
		return ""
	}
	// The SSID here is raw bytes, not UTF-16: an SSID is a byte string with no
	// declared encoding, and Windows stores exactly what the access point sent.
	ssid := hint[4 : 4+length]
	for len(ssid) > 0 && ssid[len(ssid)-1] == 0 {
		ssid = ssid[:len(ssid)-1]
	}
	return string(ssid)
}

// resolve names the network behind an L2ProfileId. Zero means "not a wireless
// connection" rather than an unknown profile, so it is left blank.
func (p srumWLANProfiles) resolve(id int32) string {
	if p == nil || id == 0 {
		return ""
	}
	if ssid, ok := p[id]; ok {
		return ssid
	}
	return "profile " + strconv.FormatInt(int64(id), 10)
}
