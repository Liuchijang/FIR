package cmd

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Liuchijang/FIR/internal/console"
	"github.com/Liuchijang/FIR/internal/module"
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
	cancelled bool
	err       error
}

func runUnifiedInteractive() error {
	console.EnsureInteractive()

	model := unifiedInteractiveModel{
		stage: stageMenu,
		menu:  tui.NewInteractiveMenuTeaModel(),
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
		m.menu = tui.NewInteractiveMenuTeaModel()
	}
	return m.menu.Init()
}

func (m unifiedInteractiveModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.stage {
	case stageCollection:
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
			m.updates = nil
		}
		return m, cmd

	default:
		updated, cmd := m.menu.Update(msg)
		m.menu = updated

		done, modules, cancelled, err := tui.InteractiveMenuFinished(updated)
		if err != nil {
			m.err = err
			return m, tea.Quit
		}
		if !done {
			return m, cmd
		}
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
	if concurrencyFlag == 0 {
		concurrencyFlag = 2
	}
	if timeoutFlag == 0 {
		timeoutFlag = 5 * time.Minute
	}

	updates := make(chan tea.Msg)
	console.SyncBufferToWindow()

	m.stage = stageCollection
	m.updates = updates
	m.progress = tui.NewCollectionProgressModel(modules, concurrencyFlag)
	return m, tea.Batch(
		m.progress.Init(),
		startCollectionCmd(modules, updates),
		waitForCollectionUpdate(updates),
	)
}
