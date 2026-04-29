package cmd

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Liuchijang/FIR/internal/collection"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/tui"
)

func startCollectionCmd(ctx context.Context, collectors []module.Module, runtimeCfg runtimeConfig, updates chan<- tea.Msg) tea.Cmd {
	return func() tea.Msg {
		go func() {
			report, err := collection.Run(ctx, collectors, runtimeCfg.CollectionOptions(true, collection.Callbacks{
				OnOutputReady: func(path string) {
					sendCollectionUpdate(ctx, updates, tui.OutputReadyMsg{Path: path})
				},
				OnModuleStart: func(index int, _ module.Module) {
					sendCollectionUpdate(ctx, updates, tui.CollectorStartedMsg{Index: index})
				},
				OnModuleFinish: func(index int, result module.Result) {
					sendCollectionUpdate(ctx, updates, tui.CollectorFinishedMsg{Index: index, Result: result})
				},
			}))
			sendCollectionUpdate(ctx, updates, tui.CollectionFinishedMsg{Report: report, Err: err})
			close(updates)
		}()
		return nil
	}
}

func sendCollectionUpdate(ctx context.Context, updates chan<- tea.Msg, msg tea.Msg) {
	select {
	case updates <- msg:
	case <-ctx.Done():
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
