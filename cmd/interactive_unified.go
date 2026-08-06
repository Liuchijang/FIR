package cmd

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/resource"
	"github.com/Liuchijang/FIR/internal/tui"
)

type interactiveStage int

const (
	stageMenu interactiveStage = iota
	stageCollection
)

type unifiedInteractiveModel struct {
	stage     interactiveStage
	menu      tea.Model
	progress  tui.CollectionProgressModel
	updates   chan tea.Msg
	resources resource.Config
	cancel    context.CancelFunc
	cancelled bool
	err       error
}

func runUnifiedInteractive() error {
	console.EnsureInteractive()

	model := unifiedInteractiveModel{
		stage:     stageMenu,
		menu:      tui.NewInteractiveMenuTeaModelWithConfig(runtimeConfigFromFlags().OutputBaseDir, runtimeConfigFromFlags().Resources),
		resources: runtimeConfigFromFlags().Resources,
	}

	program := tea.NewProgram(model, tea.WithAltScreen(), tea.WithMouseAllMotion())
	finalModel, err := program.Run()
	if err != nil {
		return err
	}

	finished, ok := finalModel.(unifiedInteractiveModel)
	if !ok {
		return nil
	}
	return finished.err
}

func (m unifiedInteractiveModel) Init() tea.Cmd {
	if m.menu == nil {
		runtimeCfg := runtimeConfigFromFlags()
		m.menu = tui.NewInteractiveMenuTeaModelWithConfig(runtimeCfg.OutputBaseDir, runtimeCfg.Resources)
	}
	return m.menu.Init()
}

func (m unifiedInteractiveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.stage {
	case stageCollection:
		if keyMsg, ok := msg.(tea.KeyMsg); ok && keyMsg.String() == "ctrl+c" && m.cancel != nil {
			m.cancel()
			m.cancel = nil
		}
		updated, cmd := m.progress.Update(msg)
		progress, ok := updated.(tui.CollectionProgressModel)
		if ok {
			m.progress = progress
			if progress.RunError() != nil {
				m.err = progress.RunError()
			}
		}

		switch msg.(type) {
		case tui.OutputReadyMsg, tui.CollectorStartedMsg, tui.CollectorFinishedMsg:
			if m.updates != nil {
				return m, tea.Batch(cmd, waitForCollectionUpdate(m.updates))
			}
		case tui.CollectionFinishedMsg:
			if m.cancel != nil {
				m.cancel()
				m.cancel = nil
			}
			m.updates = nil
		}
		return m, cmd

	default:
		updated, cmd := m.menu.Update(msg)
		m.menu = updated

		done, result, cancelled, err := tui.InteractiveMenuFinishedWithConfig(updated)
		if err != nil {
			m.err = err
			return m, tea.Quit
		}
		if !done {
			return m, cmd
		}
		modules := result.Modules
		m.resources = result.Resources
		if cancelled || len(modules) == 0 {
			m.cancelled = true
			return m, tea.Quit
		}

		return m.startCollection(modules)
	}
}

func (m unifiedInteractiveModel) View() string {
	switch m.stage {
	case stageCollection:
		return m.progress.View()
	default:
		if m.menu == nil {
			return ""
		}
		return m.menu.View()
	}
}

func (m unifiedInteractiveModel) startCollection(modules []module.Module) (tea.Model, tea.Cmd) {
	runtimeCfg := runtimeConfigFromFlags()
	runtimeCfg.Resources = m.resources.Normalized().ResolveWorkers(runtimeCfg.OutputBaseDir)

	updates := make(chan tea.Msg, len(modules)*2+2)
	ctx, cancel := context.WithCancel(context.Background())
	console.SyncBufferToWindow()

	m.stage = stageCollection
	m.updates = updates
	m.cancel = cancel
	m.progress = tui.NewCollectionProgressModel(modules, runtimeCfg.Resources.WorkerSummary())
	return m, tea.Batch(
		m.progress.Init(),
		startCollectionCmd(ctx, modules, runtimeCfg, updates),
		waitForCollectionUpdate(updates),
	)
}
