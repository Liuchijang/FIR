package acquisition

import "strings"

// RawVolumePool lazily opens and caches a RawVolume (and its NTFS metadata)
// per drive letter, so many raw-fallback reads within one collector run reuse
// the same open volume handle (and, via RawVolume's own MFT path index, the
// same in-memory MFT scan) instead of every caller re-implementing this
// caching. Close releases every volume this pool opened.
type RawVolumePool struct {
	volumes map[string]*pooledVolume
}

type pooledVolume struct {
	vol     *RawVolume
	volData *NTFSVolumeData
}

func (p *RawVolumePool) Get(drive string) (*RawVolume, *NTFSVolumeData, error) {
	if p.volumes == nil {
		p.volumes = make(map[string]*pooledVolume)
	}
	if v, ok := p.volumes[drive]; ok {
		return v.vol, v.volData, nil
	}

	vol, err := OpenRawVolume(drive)
	if err != nil {
		return nil, nil, err
	}
	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		vol.Close()
		return nil, nil, err
	}

	p.volumes[drive] = &pooledVolume{vol: vol, volData: volData}
	return vol, volData, nil
}

func (p *RawVolumePool) CopyFile(path, outputPath string) (int64, error) {
	vol, volData, err := p.Get(driveLetterOf(path))
	if err != nil {
		return 0, err
	}
	return CopyFileFromRawPath(vol, volData, path, outputPath)
}

func (p *RawVolumePool) Close() {
	for _, v := range p.volumes {
		v.vol.Close()
	}
}

func driveLetterOf(path string) string {
	if len(path) >= 2 && path[1] == ':' {
		return strings.ToUpper(string(path[0]))
	}
	return "C"
}
