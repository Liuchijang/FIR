package jumplist

import "github.com/Liuchijang/Tyto/internal/winguid"

// GUID is internal/winguid's, aliased so a caller of this package does not have
// to know where the droid arithmetic lives.
type GUID = winguid.GUID

func guidAt(record []byte, offset int) GUID { return winguid.At(record, offset) }
