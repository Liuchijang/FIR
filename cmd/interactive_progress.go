package cmd

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/tui"
)

func startCollectionCmd(collectors []module.Module, updates chan<- tea.Msg) tea.Cmd {
	return func() tea.Msg {
		go func() {
			report, err := executeCollectionWithOptions(collectors, collectionOptions{
				SilentConsole: true,
				Callbacks: collectionCallbacks{
					OnOutputReady: func(path string) {
						updates <- tui.OutputReadyMsg{Path: path}
					},
					OnModuleStart: func(index int, _ module.Module) {
						updates <- tui.CollectorStartedMsg{Index: index}
					},
					OnModuleFinish: func(index int, result module.Result) {
						updates <- tui.CollectorFinishedMsg{Index: index, Result: result}
					},
				},
			})
			updates <- tui.CollectionFinishedMsg{Report: report, Err: err}
			close(updates)
		}()
		return nil
	}
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
