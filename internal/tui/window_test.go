package tui

import "testing"

// The rendered block is the window plus its indicator lines. If that total exceeds
// visibleRows the viewport clips the last line, which is the cursor row whenever the
// list is scrolled to the bottom.
func TestWindowForNeverExceedsRowBudget(t *testing.T) {
	for _, total := range []int{1, 2, 5, 11, 50, 500} {
		for _, visibleRows := range []int{1, 2, 3, 5, 10, 49} {
			for cursor := 0; cursor < total; cursor++ {
				w := windowFor(total, cursor, visibleRows)
				if w.rows() > visibleRows {
					t.Errorf("total=%d rows=%d cursor=%d: renders %d lines, budget is %d",
						total, visibleRows, cursor, w.rows(), visibleRows)
				}
				if w.start < 0 || w.end > total || w.start >= w.end {
					t.Fatalf("total=%d rows=%d cursor=%d: invalid bounds [%d,%d)",
						total, visibleRows, cursor, w.start, w.end)
				}
			}
		}
	}
}

// Scrolling to either end must keep the cursor's own row inside the window.
func TestWindowForKeepsCursorVisible(t *testing.T) {
	for _, total := range []int{1, 2, 5, 11, 50, 500} {
		for _, visibleRows := range []int{1, 2, 3, 5, 10} {
			for cursor := 0; cursor < total; cursor++ {
				w := windowFor(total, cursor, visibleRows)
				if cursor < w.start || cursor >= w.end {
					t.Errorf("total=%d rows=%d cursor=%d: cursor outside window [%d,%d)",
						total, visibleRows, cursor, w.start, w.end)
				}
			}
		}
	}
}

func TestWindowForShowsWholeListWhenItFits(t *testing.T) {
	w := windowFor(5, 2, 10)
	if w.start != 0 || w.end != 5 || w.above != 0 || w.below != 0 {
		t.Errorf("windowFor(5,2,10) = %+v, want the whole list with no indicators", w)
	}
}

func TestWindowForEmptyList(t *testing.T) {
	if w := windowFor(0, 0, 10); w.rows() != 0 {
		t.Errorf("windowFor(0,...) = %+v, want an empty window", w)
	}
	if w := windowFor(10, 0, 0); w.rows() != 0 {
		t.Errorf("windowFor(...,0) = %+v, want an empty window", w)
	}
}
