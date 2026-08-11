package analyzers

import (
	"strconv"
	"strings"
)

// SRUM stores one ESE table per data provider, named after the provider's GUID.
// The names below are the providers whose column sets identify them
// unambiguously — every one was confirmed against a real SRUDB.dat rather than
// taken on trust, because a wrong provider label on a CSV is worse for an
// analyst than a raw GUID.
//
// A provider that is not in this map still gets exported; it is named after its
// GUID. Windows adds providers between releases, and dropping an unknown table
// would silently discard the one artifact the analyst came for.
var srumTableNames = map[string]string{
	// Foreground/background CPU, disk and I/O per application. The table most
	// SRUM analysis starts from.
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}": "application_resource_usage",
	// NotificationType/PayloadSize/NetworkType.
	"{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}": "push_notification_data",
	// In-focus, user-input and render timelines per application.
	"{5C8CF1C7-7257-4F13-B223-970EF5939312}": "application_timeline",
	// BytesSent/BytesRecvd per application per interface.
	"{973F5D5C-1D90-4944-BE8E-24B94231A174}": "network_data_usage",
	// ConnectedTime/ConnectStartTime per interface: when the machine was on
	// which network.
	"{DD6636C4-8929-4683-974E-22C046A43763}": "network_connectivity_usage",
	// Battery and energy counters.
	"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}":   "energy_usage",
	"{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT": "energy_usage_long_term",
}

// Providers beyond the seven above are named at runtime from Windows' own
// registration under srumExtensionsKey, not from a list shipped in this file.
//
// An earlier version transcribed ten further GUID-to-name pairs out of
// srum-dump's configuration. That tool is GPL-3.0 and FIR is not, and while a
// Windows component's name is not itself much of a creative work, the selection
// and arrangement of a provider table plausibly is. Reading the registry gets the
// same information from Microsoft, covers providers no third-party list knows
// about yet, and leaves nothing to argue about.

// srumInternalTables are ESE bookkeeping and the lookup table itself. The ID map
// is not exported as a provider table because every provider row already carries
// its resolved values.
var srumInternalTables = map[string]bool{
	"MSysObjects":          true,
	"MSysObjectsShadow":    true,
	"MSysObjids":           true,
	"MSysLocales":          true,
	"SruDbIdMapTable":      true,
	"SruDbCheckpointTable": true,
}

// srumFiletimeColumns hold a Windows FILETIME as a 64-bit integer. The
// TimeStamp column is not among them: the ESE column type there is DateTime and
// the reader hands it back already decoded.
var srumFiletimeColumns = map[string]bool{
	"StartTime":        true,
	"EndTime":          true,
	"ConnectStartTime": true,
}

// srumColumnHeaders renames the ESE column names that do not say what they hold.
//
// FIR's other analyzers already name their columns descriptively rather than
// after the on-disk structure — mft_parser writes SI_CreatedUTC, not the
// attribute offset — and the UTC suffix on every timestamp is what makes an
// output directory joinable. Anything not listed keeps its ESE name, which is
// both accurate and stable across Windows releases.
//
// Two of srum-dump's labels are deliberately not adopted. "CPU time in
// Forground" carries a typo and, worse, is wrong: ForegroundCycleTime counts CPU
// cycles, not time, and relabelling it as time invites an analyst to read it as
// milliseconds. "Flags (BinaryData)" describes the storage rather than the
// meaning. The original names are more truthful in both cases.
var srumColumnHeaders = map[string]string{
	"AutoIncId":        "SrumEntryId",
	"TimeStamp":        "SrumEntryCreationUTC",
	"StartTime":        "StartTimeUTC",
	"EndTime":          "EndTimeUTC",
	"ConnectStartTime": "ConnectStartTimeUTC",
	"EventTimestamp":   "EventTimestampUTC",
	"BytesRecvd":       "BytesReceived",
	"ChargeLevel":      "BatteryChargeLevel",
}

// srumColumnHeader renders one column's CSV heading.
func srumColumnHeader(column string) string {
	if friendly, ok := srumColumnHeaders[column]; ok {
		return friendly
	}
	return column
}

// srumSecondsColumns hold a whole number of seconds. Each gets a companion
// column rendering the same number as a duration, because "97912" is a value an
// analyst has to divide by hand before it means "27 hours on this network".
var srumSecondsColumns = map[string]bool{
	"ConnectedTime":       true,
	"ActiveAcTime":        true,
	"CsAcTime":            true,
	"ActiveDcTime":        true,
	"CsDcTime":            true,
	"ActiveDischargeTime": true,
	"CsDischargeTime":     true,
}

// Provider tables that carry computed columns.
const (
	srumNetworkDataUsageTable   = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
	srumNetworkConnectivityable = "{DD6636C4-8929-4683-974E-22C046A43763}"
)

// srumTableFileName maps a table to the CSV it is written to.
//
// discovered holds the provider names read from the registry for this run. The
// built-in table wins over it: those seven were each confirmed against a real
// database by their column sets, whereas a registry string is whatever the
// installed build happens to say.
func srumTableFileName(table string, discovered map[string]string) string {
	upper := strings.ToUpper(table)
	if name, ok := srumTableNames[upper]; ok {
		return "srum_" + name + ".csv"
	}
	if name, ok := discovered[upper]; ok && name != "" {
		return "srum_" + name + ".csv"
	}
	// The Energy Usage long-term table is the same GUID with an LT suffix, so a
	// registry hit on the bare GUID still names it usefully.
	if trimmed, cut := strings.CutSuffix(upper, "LT"); cut {
		if name, ok := discovered[trimmed]; ok && name != "" {
			return "srum_" + name + "_long_term.csv"
		}
	}
	// Braces and spaces would survive into a filename an analyst has to type.
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, table)
	if cleaned == "" {
		return "srum_unnamed.csv"
	}
	return "srum_" + cleaned + ".csv"
}

// srumInterfaceType decodes the interface type out of a NET_LUID.
//
// A LUID is not an index: its top 16 bits are the NDIS interface type, so
// "InterfaceLuid 1689399683186688" is an Ethernet adapter. Without this the
// column is an opaque 16-digit number and there is no way to tell a wired
// session from a Wi-Fi one.
func srumInterfaceType(luid uint64) string {
	ifType := luid >> 48
	if name, ok := srumInterfaceTypes[ifType]; ok {
		return name
	}
	return "IF_TYPE_" + strconv.FormatUint(ifType, 10)
}

// srumInterfaceTypes is the IANA ifType registry as SRUM reports it, complete
// rather than abridged: the values are a published enumeration, so carrying all
// of it costs nothing and means an adapter type never has to be looked up by
// hand. A value outside the registry is rendered numerically by
// srumInterfaceType rather than guessed at.
var srumInterfaceTypes = map[uint64]string{
	1:   "IF_TYPE_OTHER",
	2:   "IF_TYPE_REGULAR_1822",
	3:   "IF_TYPE_HDH_1822",
	4:   "IF_TYPE_DDN_X25",
	5:   "IF_TYPE_RFC877_X25",
	6:   "IF_TYPE_ETHERNET_CSMACD",
	7:   "IF_TYPE_IS088023_CSMACD",
	8:   "IF_TYPE_ISO88024_TOKENBUS",
	9:   "IF_TYPE_ISO88025_TOKENRING",
	10:  "IF_TYPE_ISO88026_MAN",
	11:  "IF_TYPE_STARLAN",
	12:  "IF_TYPE_PROTEON_10MBIT",
	13:  "IF_TYPE_PROTEON_80MBIT",
	14:  "IF_TYPE_HYPERCHANNEL",
	15:  "IF_TYPE_FDDI",
	16:  "IF_TYPE_LAP_B",
	17:  "IF_TYPE_SDLC",
	18:  "IF_TYPE_DS1",
	19:  "IF_TYPE_E1",
	20:  "IF_TYPE_BASIC_ISDN",
	21:  "IF_TYPE_PRIMARY_ISDN",
	22:  "IF_TYPE_PROP_POINT2POINT_SERIAL",
	23:  "IF_TYPE_PPP",
	24:  "IF_TYPE_SOFTWARE_LOOPBACK",
	25:  "IF_TYPE_EON",
	26:  "IF_TYPE_ETHERNET_3MBIT",
	27:  "IF_TYPE_NSIP",
	28:  "IF_TYPE_SLIP",
	29:  "IF_TYPE_ULTRA",
	30:  "IF_TYPE_DS3",
	31:  "IF_TYPE_SIP",
	32:  "IF_TYPE_FRAMERELAY",
	33:  "IF_TYPE_RS232",
	34:  "IF_TYPE_PARA",
	35:  "IF_TYPE_ARCNET",
	36:  "IF_TYPE_ARCNET_PLUS",
	37:  "IF_TYPE_ATM",
	38:  "IF_TYPE_MIO_X25",
	39:  "IF_TYPE_SONET",
	40:  "IF_TYPE_X25_PLE",
	41:  "IF_TYPE_ISO88022_LLC",
	42:  "IF_TYPE_LOCALTALK",
	43:  "IF_TYPE_SMDS_DXI",
	44:  "IF_TYPE_FRAMERELAY_SERVICE",
	45:  "IF_TYPE_V35",
	46:  "IF_TYPE_HSSI",
	47:  "IF_TYPE_HIPPI",
	48:  "IF_TYPE_MODEM",
	49:  "IF_TYPE_AAL5",
	50:  "IF_TYPE_SONET_PATH",
	51:  "IF_TYPE_SONET_VT",
	52:  "IF_TYPE_SMDS_ICIP",
	53:  "IF_TYPE_PROP_VIRTUAL",
	54:  "IF_TYPE_PROP_MULTIPLEXOR",
	55:  "IF_TYPE_IEEE80212",
	56:  "IF_TYPE_FIBRECHANNEL",
	57:  "IF_TYPE_HIPPIINTERFACE",
	58:  "IF_TYPE_FRAMERELAY_INTERCONNECT",
	59:  "IF_TYPE_AFLANE_8023",
	60:  "IF_TYPE_AFLANE_8025",
	61:  "IF_TYPE_CCTEMUL",
	62:  "IF_TYPE_FASTETHER",
	63:  "IF_TYPE_ISDN",
	64:  "IF_TYPE_V11",
	65:  "IF_TYPE_V36",
	66:  "IF_TYPE_G703_64K",
	67:  "IF_TYPE_G703_2MB",
	68:  "IF_TYPE_QLLC",
	69:  "IF_TYPE_FASTETHER_FX",
	70:  "IF_TYPE_CHANNEL",
	71:  "IF_TYPE_IEEE80211",
	72:  "IF_TYPE_IBM370PARCHAN",
	73:  "IF_TYPE_ESCON",
	74:  "IF_TYPE_DLSW",
	75:  "IF_TYPE_ISDN_S",
	76:  "IF_TYPE_ISDN_U",
	77:  "IF_TYPE_LAP_D",
	78:  "IF_TYPE_IPSWITCH",
	79:  "IF_TYPE_RSRB",
	80:  "IF_TYPE_ATM_LOGICAL",
	81:  "IF_TYPE_DS0",
	82:  "IF_TYPE_DS0_BUNDLE",
	83:  "IF_TYPE_BSC",
	84:  "IF_TYPE_ASYNC",
	85:  "IF_TYPE_CNR",
	86:  "IF_TYPE_ISO88025R_DTR",
	87:  "IF_TYPE_EPLRS",
	88:  "IF_TYPE_ARAP",
	89:  "IF_TYPE_PROP_CNLS",
	90:  "IF_TYPE_HOSTPAD",
	91:  "IF_TYPE_TERMPAD",
	92:  "IF_TYPE_FRAMERELAY_MPI",
	93:  "IF_TYPE_X213",
	94:  "IF_TYPE_ADSL",
	95:  "IF_TYPE_RADSL",
	96:  "IF_TYPE_SDSL",
	97:  "IF_TYPE_VDSL",
	98:  "IF_TYPE_ISO88025_CRFPRINT",
	99:  "IF_TYPE_MYRINET",
	100: "IF_TYPE_VOICE_EM",
	101: "IF_TYPE_VOICE_FXO",
	102: "IF_TYPE_VOICE_FXS",
	103: "IF_TYPE_VOICE_ENCAP",
	104: "IF_TYPE_VOICE_OVERIP",
	105: "IF_TYPE_ATM_DXI",
	106: "IF_TYPE_ATM_FUNI",
	107: "IF_TYPE_ATM_IMA",
	108: "IF_TYPE_PPPMULTILINKBUNDLE",
	109: "IF_TYPE_IPOVER_CDLC",
	110: "IF_TYPE_IPOVER_CLAW",
	111: "IF_TYPE_STACKTOSTACK",
	112: "IF_TYPE_VIRTUALIPADDRESS",
	113: "IF_TYPE_MPC",
	114: "IF_TYPE_IPOVER_ATM",
	115: "IF_TYPE_ISO88025_FIBER",
	116: "IF_TYPE_TDLC",
	117: "IF_TYPE_GIGABITETHERNET",
	118: "IF_TYPE_HDLC",
	119: "IF_TYPE_LAP_F",
	120: "IF_TYPE_V37",
	121: "IF_TYPE_X25_MLP",
	122: "IF_TYPE_X25_HUNTGROUP",
	123: "IF_TYPE_TRANSPHDLC",
	124: "IF_TYPE_INTERLEAVE",
	125: "IF_TYPE_FAST",
	126: "IF_TYPE_IP",
	127: "IF_TYPE_DOCSCABLE_MACLAYER",
	128: "IF_TYPE_DOCSCABLE_DOWNSTREAM",
	129: "IF_TYPE_DOCSCABLE_UPSTREAM",
	130: "IF_TYPE_A12MPPSWITCH",
	131: "IF_TYPE_TUNNEL",
	132: "IF_TYPE_COFFEE",
	133: "IF_TYPE_CES",
	134: "IF_TYPE_ATM_SUBINTERFACE",
	135: "IF_TYPE_L2_VLAN",
	136: "IF_TYPE_L3_IPVLAN",
	137: "IF_TYPE_L3_IPXVLAN",
	138: "IF_TYPE_DIGITALPOWERLINE",
	139: "IF_TYPE_MEDIAMAILOVERIP",
	140: "IF_TYPE_DTM",
	141: "IF_TYPE_DCN",
	142: "IF_TYPE_IPFORWARD",
	143: "IF_TYPE_MSDSL",
	144: "IF_TYPE_IEEE1394",
	145: "IF_TYPE_RECEIVE_ONLY",
}

// srumKnownSIDs labels the well-known accounts SRUM records activity for, so a
// UserId does not have to be resolved by hand. Domain and local user SIDs are
// left as the raw SID string — this tool has no way to name them and inventing
// a label would be worse than the SID.
var srumKnownSIDs = map[string]string{
	"S-1-0-0":      "Nobody",
	"S-1-1-0":      "Everyone",
	"S-1-2-0":      "Local",
	"S-1-3-0":      "Creator Owner",
	"S-1-5-6":      "Service",
	"S-1-5-7":      "Anonymous",
	"S-1-5-11":     "Authenticated Users",
	"S-1-5-17":     "IUSR",
	"S-1-5-18":     "Local System",
	"S-1-5-19":     "Local Service",
	"S-1-5-20":     "Network Service",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-555": "Remote Desktop Users",
	"S-1-5-32-559": "Performance Log Users",
	"S-1-5-80-0":   "All Services",
	"S-1-5-90-0":   "Window Manager Group",
	"S-1-15-2-1":   "All Application Packages",
	"S-1-16-4096":  "Low Mandatory Level",
	"S-1-16-8192":  "Medium Mandatory Level",
	"S-1-16-12288": "High Mandatory Level",
	"S-1-16-16384": "System Mandatory Level",
	"S-1-5-113":    "Local Account",
	"S-1-5-114":    "Local Account And Member Of Administrators Group",
	"S-1-5-33":     "Write Restricted Code",
	"S-1-5-64-10":  "NTLM Authentication",
	"S-1-5-64-14":  "SChannel Authentication",
	"S-1-5-64-21":  "Digest Authentication",
	"S-1-5-90-0-1": "Window Manager\\DWM-1",
	"S-1-5-90-0-2": "Window Manager\\DWM-2",
	"S-1-5-90-0-3": "Window Manager\\DWM-3",
	"S-1-5-96-0-0": "Font Driver Host\\UMFD-0",
	"S-1-5-96-0-1": "Font Driver Host\\UMFD-1",
	"S-1-5-96-0-2": "Font Driver Host\\UMFD-2",
	"S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420": "NT SERVICE\\WdiServiceHost",
}

// srumLabelSID appends the well-known account name when there is one.
func srumLabelSID(sid string) string {
	if sid == "" {
		return ""
	}
	if name, ok := srumKnownSIDs[sid]; ok {
		return sid + " (" + name + ")"
	}
	return sid
}
