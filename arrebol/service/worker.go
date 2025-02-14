package service

import (
	"github.com/hashicorp/go-uuid"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/service/driver"
	"github.com/ufcg-lsd/arrebol-pb/storage"
)

type Worker struct {
	id     string
	driver driver.Driver
	state  WorkerState
}

type WorkerState uint

const (
	Sleeping WorkerState = iota
	Working
	Busy
)

func NewWorker(driver2 driver.Driver) *Worker {
	id, _ := uuid.GenerateUUID()
	return &Worker{
		id:     id,
		driver: driver2,
		state:  Sleeping,
	}
}

func (w *Worker) MatchAny(task *storage.Task) bool {
	return w.state == Sleeping
}

func (w *Worker) Execute(task *storage.Task) {
	w.state = Working
	task.State = storage.TaskRunning
	_ = storage.DB.SaveTask(task)
	w.driver.Execute(task)
	_ = storage.DB.SaveTask(task)
	w.state = Sleeping
}
