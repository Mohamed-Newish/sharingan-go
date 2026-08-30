// Package banner prints the startup Sharingan-eye banner. The eye is
// pixel data (see eye_data.go, generated — not hand-authored ASCII art),
// rendered with the Unicode half-block trick: each terminal character
// cell shows two vertically-stacked pixels — foreground color for the
// top half, background color for the bottom — via '▀'/'▄', doubling the
// effective vertical resolution for the same number of printed lines.
package banner

import (
	"fmt"
	"io"
	"os"
)

// tag -> truecolor hex, matching the digits in eye_data.go's rows.
// "" (tag '0') means transparent: let the terminal's own background
// show through instead of forcing a color, so the banner looks right
// in both dark and (less ideally, but not broken) light terminals.
var palette = map[byte]string{
	'0': "",       // outside the eye
	'1': "a9b4bf", // sclera
	'2': "c81d3f", // iris
	'3': "2a0a10", // tomoe
	'4': "08090a", // pupil
}

// Enabled reports whether the banner should print: stdout is an actual
// terminal (not piped/redirected — never pollute scripted/logged
// output) and the user hasn't opted out via NO_COLOR or SHARINGAN_NO_BANNER.
func Enabled() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("SHARINGAN_NO_BANNER") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Print writes the eye banner to w, two pixel-rows per printed line.
func Print(w io.Writer) {
	for r := 0; r+1 < len(rows); r += 2 {
		top, bot := rows[r], rows[r+1]
		for c := 0; c < len(top); c++ {
			writeCell(w, top[c], bot[c])
		}
		fmt.Fprintln(w)
	}
}

// writeCell prints one terminal character cell for a top/bottom pixel
// pair. Whichever half is transparent, the other is drawn with a half
// block so only that half's color shows against the terminal's own
// background — never a forced opaque background for the "outside the
// eye" area.
func writeCell(w io.Writer, top, bot byte) {
	fg, bg := palette[top], palette[bot]
	switch {
	case fg == "" && bg == "":
		fmt.Fprint(w, " ")
	case fg != "" && bg != "":
		fmt.Fprintf(w, "\x1b[38;2;%sm\x1b[48;2;%sm▀\x1b[0m", hexRGB(fg), hexRGB(bg))
	case fg != "":
		fmt.Fprintf(w, "\x1b[38;2;%sm▀\x1b[0m", hexRGB(fg))
	default:
		fmt.Fprintf(w, "\x1b[38;2;%sm▄\x1b[0m", hexRGB(bg))
	}
}

// hexRGB turns "c81d3f" into "200;29;63" (the R;G;B form the 24-bit
// SGR codes 38/48;2;... expect).
func hexRGB(hex string) string {
	var r, g, b int
	fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b)
	return fmt.Sprintf("%d;%d;%d", r, g, b)
}
