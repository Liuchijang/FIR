//go:build !windows

package resource

func DetectMediaKind(string) MediaKind { return MediaUnknown }

func SurveyStorage(string) StorageSurvey {
	unknown := StorageDevice{Media: MediaUnknown, Bus: BusTypeUnknown}
	return StorageSurvey{Output: unknown, Sources: []StorageDevice{unknown}}
}
