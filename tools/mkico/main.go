// Command mkico builds Tyto's Windows icon from its source PNG.
//
// It exists so tyto.ico is a reproducible artifact rather than a binary blob
// nobody can regenerate: point it at a new drawing and the whole icon set comes
// out again. The .ico then becomes tyto_windows_amd64.syso, which the Go linker
// picks up automatically — see the icon section in README.md.
//
// Deliberately standard-library only. It is a build tool, and pulling an imaging
// dependency into go.mod for something that runs once would put it in the
// dependency list of a forensic binary that ships as a single static executable.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

// iconSizes are the sizes Windows picks between: list view and the taskbar take
// the small end, Alt-Tab and the file properties dialog the large.
var iconSizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

func main() {
	source := flag.String("in", "tyto.png", "source PNG")
	dest := flag.String("out", "tyto.ico", "destination ICO")
	background := flag.String("bg", "", "background as RRGGBB; empty keeps the source's transparency")
	margin := flag.Float64("margin", 0.10, "padding around the drawing, as a fraction of its longest side")
	sheet := flag.String("sheet", "", "also write a light/dark preview sheet here")
	flag.Parse()

	art, err := loadPNG(*source)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkico:", err)
		os.Exit(1)
	}

	square := cropToSquare(art, *margin)
	if *background != "" {
		// Worth knowing before reaching for this: the ICO ships transparent by
		// choice, but the drawing is a black silhouette, and Windows paints a
		// dark-mode taskbar near-black. Run with -sheet to see what a given
		// background does at 16px before committing one.
		colour, err := parseHexColour(*background)
		if err != nil {
			fmt.Fprintln(os.Stderr, "mkico:", err)
			os.Exit(1)
		}
		square = flatten(square, colour)
	}

	entries := make([][]byte, 0, len(iconSizes))
	for _, size := range iconSizes {
		scaled := resize(square, size)
		if size >= 256 {
			// Only the largest entry is PNG-compressed. Windows has read those since
			// Vista, but a 16x16 PNG entry is larger than the DIB it replaces and
			// some shell extensions still expect a DIB at the small sizes.
			entries = append(entries, encodePNG(scaled))
			continue
		}
		entries = append(entries, encodeDIB(scaled))
	}

	if err := os.WriteFile(*dest, buildICO(entries), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "mkico:", err)
		os.Exit(1)
	}
	fmt.Printf("%s: %v\n", *dest, iconSizes)

	if *sheet != "" {
		if err := writePreviewSheet(*sheet, square); err != nil {
			fmt.Fprintln(os.Stderr, "mkico:", err)
			os.Exit(1)
		}
		fmt.Printf("%s: light and dark preview\n", *sheet)
	}
}

func loadPNG(path string) (*image.RGBA, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoded, err := png.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	out := image.NewRGBA(decoded.Bounds())
	draw.Draw(out, out.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	return out, nil
}

// cropToSquare centres the square on the drawing rather than on the canvas: the
// source art sits off-centre in its frame, and an icon cropped to the frame would
// be off-centre in every shell that shows it.
func cropToSquare(src *image.RGBA, margin float64) *image.RGBA {
	bounds := src.Bounds()
	minX, minY := bounds.Max.X, bounds.Max.Y
	maxX, maxY := bounds.Min.X, bounds.Min.Y
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if src.RGBAAt(x, y).A > 0x7F {
				minX, minY = min(minX, x), min(minY, y)
				maxX, maxY = max(maxX, x), max(maxY, y)
			}
		}
	}
	if minX > maxX {
		return src // nothing drawn; leave it to the caller's eyes
	}

	width, height := maxX-minX+1, maxY-minY+1
	side := int(float64(max(width, height)) * (1 + 2*margin))
	out := image.NewRGBA(image.Rect(0, 0, side, side))
	// Source pixels outside the canvas read as transparent, which is what the
	// padding should be anyway.
	draw.Draw(out, out.Bounds(), src, image.Pt((minX+maxX)/2-side/2, (minY+maxY)/2-side/2), draw.Src)
	return out
}

func flatten(src *image.RGBA, background color.RGBA) *image.RGBA {
	out := image.NewRGBA(src.Bounds())
	draw.Draw(out, out.Bounds(), &image.Uniform{background}, image.Point{}, draw.Src)
	draw.Draw(out, out.Bounds(), src, src.Bounds().Min, draw.Over)
	return out
}

// resize area-averages. That is the right filter for flat-colour art: it
// antialiases the edges without the ringing a cubic filter leaves along a hard
// silhouette, which at 16x16 shows up as a grey halo.
func resize(src *image.RGBA, size int) *image.RGBA {
	bounds := src.Bounds()
	out := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := float64(bounds.Dx()) / float64(size)

	for y := range size {
		for x := range size {
			x0, x1 := int(float64(x)*scale), int(float64(x+1)*scale)
			y0, y1 := int(float64(y)*scale), int(float64(y+1)*scale)
			x1, y1 = max(x1, x0+1), max(y1, y0+1)

			var red, green, blue, alpha, count uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					p := src.RGBAAt(bounds.Min.X+sx, bounds.Min.Y+sy)
					// Premultiplied, so a transparent pixel's colour cannot bleed into
					// the average and wash out the edge.
					red += uint64(p.R) * uint64(p.A) / 255
					green += uint64(p.G) * uint64(p.A) / 255
					blue += uint64(p.B) * uint64(p.A) / 255
					alpha += uint64(p.A)
					count++
				}
			}
			if count == 0 {
				continue
			}

			mean := uint8(alpha / count)
			unpremultiply := func(sum uint64) uint8 {
				if mean == 0 {
					return 0
				}
				return uint8(min(sum/count*255/uint64(mean), 255))
			}
			out.SetRGBA(x, y, color.RGBA{
				unpremultiply(red), unpremultiply(green), unpremultiply(blue), mean,
			})
		}
	}
	return out
}

func encodePNG(img *image.RGBA) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err) // an in-memory RGBA cannot fail to encode
	}
	return buf.Bytes()
}

// encodeDIB writes the device-independent bitmap an ICONDIRENTRY expects: a
// BITMAPINFOHEADER whose height covers the colour rows and the AND mask together,
// bottom-up BGRA rows, then the 1-bit mask.
//
// Modern Windows honours the alpha channel and ignores the mask, but a mask that
// contradicts it still leaks through in older shells, so it is written honestly
// rather than zeroed.
func encodeDIB(img *image.RGBA) []byte {
	width, height := img.Bounds().Dx(), img.Bounds().Dy()
	var buf bytes.Buffer

	binary.Write(&buf, binary.LittleEndian, uint32(40))
	binary.Write(&buf, binary.LittleEndian, int32(width))
	binary.Write(&buf, binary.LittleEndian, int32(2*height))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(32))
	for range 6 {
		binary.Write(&buf, binary.LittleEndian, uint32(0))
	}

	for y := height - 1; y >= 0; y-- {
		for x := range width {
			p := img.RGBAAt(x, y)
			buf.Write([]byte{p.B, p.G, p.R, p.A})
		}
	}

	stride := ((width + 31) / 32) * 4
	for y := height - 1; y >= 0; y-- {
		row := make([]byte, stride)
		for x := range width {
			if img.RGBAAt(x, y).A < 0x80 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		buf.Write(row)
	}
	return buf.Bytes()
}

func buildICO(entries [][]byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1)) // 1 = icon, 2 = cursor
	binary.Write(&buf, binary.LittleEndian, uint16(len(entries)))

	offset := 6 + 16*len(entries)
	for i, data := range entries {
		// The directory stores each dimension in one byte, so 256 is encoded as 0.
		dimension := byte(iconSizes[i])
		if iconSizes[i] >= 256 {
			dimension = 0
		}
		buf.Write([]byte{dimension, dimension, 0, 0})
		binary.Write(&buf, binary.LittleEndian, uint16(1))
		binary.Write(&buf, binary.LittleEndian, uint16(32))
		binary.Write(&buf, binary.LittleEndian, uint32(len(data)))
		binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(data)
	}
	for _, data := range entries {
		buf.Write(data)
	}
	return buf.Bytes()
}

// writePreviewSheet shows the icon at shell sizes over a light and a dark surface.
// It is the only way to catch a silhouette that disappears into Windows' dark
// mode, which the source drawing does.
func writePreviewSheet(path string, square *image.RGBA) error {
	shown := []int{16, 24, 32, 48, 128}
	const pad, band = 24, 128

	width := pad
	for _, size := range shown {
		width += size + pad
	}
	surfaces := []color.RGBA{{0xFF, 0xFF, 0xFF, 0xFF}, {0x1E, 0x1E, 0x1E, 0xFF}}

	out := image.NewRGBA(image.Rect(0, 0, width, len(surfaces)*(band+pad)+pad))
	for row, surface := range surfaces {
		top := pad/2 + row*(band+pad)
		strip := image.Rect(0, top, width, top+band+pad)
		draw.Draw(out, strip, &image.Uniform{surface}, image.Point{}, draw.Src)

		x := pad
		for _, size := range shown {
			y := strip.Min.Y + (strip.Dy()-size)/2
			draw.Draw(out, image.Rect(x, y, x+size, y+size), resize(square, size), image.Point{}, draw.Over)
			x += size + pad
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return png.Encode(file, out)
}

func parseHexColour(value string) (color.RGBA, error) {
	var r, g, b uint8
	if _, err := fmt.Sscanf(value, "%02x%02x%02x", &r, &g, &b); err != nil {
		return color.RGBA{}, fmt.Errorf("parse colour %q as RRGGBB: %w", value, err)
	}
	return color.RGBA{r, g, b, 0xFF}, nil
}
