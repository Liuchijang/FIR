package cmd

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Liuchijang/FIR/internal/collection"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/tui"
)

// startCollectionCmd runs collection in the background and streams progress over updates.
// The channel is sized to exactly fit every message this run can produce (see CollectionOptions
// call site), so sendCollectionUpdate can send unconditionally: it never blocks, and in
// particular the terminal CollectionFinishedMsg is never dropped even after ctx is cancelled
// by an abort — dropping it would leave the TUI (and the process) exiting before collection.Run
// finishes writing the manifest/summary and compressing the output directory.
func startCollectionCmd(ctx context.Context, collectors []module.Module, runtimeCfg runtimeConfig, updates chan<- tea.Msg) tea.Cmd {
	return func() tea.Msg {
		go func() {
			report, err := collection.Run(ctx, collectors, runtimeCfg.CollectionOptions(true, collection.Callbacks{
				OnOutputReady: func(path string) {
					sendCollectionUpdate(updates, tui.OutputReadyMsg{Path: path})
				},
				OnModuleStart: func(index int, _ module.Module) {
					sendCollectionUpdate(updates, tui.CollectorStartedMsg{Index: index})
				},
				OnModuleFinish: func(index int, result module.Result) {
					sendCollectionUpdate(updates, tui.CollectorFinishedMsg{Index: index, Result: result})
				},
			}))
			sendCollectionUpdate(updates, tui.CollectionFinishedMsg{Report: report, Err: err})
			close(updates)
		}()
		return nil
	}
}

func sendCollectionUpdate(updates chan<- tea.Msg, msg tea.Msg) {
	updates <- msg
}

func waitForCollectionUpdate(updates <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-updates
		if !ok {
			return nil
		}
		return msg
	}
}
