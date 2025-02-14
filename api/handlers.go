package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/ufcg-lsd/arrebol-pb/storage"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Version struct {
	Tag  string `json:"Tag"`
	Name string `json:"Name"`
}

// swagger:model QueueResponse
type QueueResponse struct {
	ID           uint   `json:"ID"`
	Name         string `json:"Name"`
	PendingTasks uint   `json:"PendingTasks"`
	RunningTasks uint   `json:"RunningTasks"`
	Nodes        uint   `json:"Nodes"`
	Workers      uint   `json:"Workers"`
}

type JobResponse struct {
	ID        uint            `json:"ID"`
	Label     string          `json:"Label"`
	State     string          `json:"State"`
	CreatedAt time.Time       `json:"CreatedAt"`
	UpdatedAt time.Time       `json:"UpdatedAt"`
	Tasks     []*TaskResponse `json:"Tasks"`
}

type TaskResponse struct {
	ID       uint               `json:"ID"`
	State    string             `json:"State"`
	Commands []*CommandResponse `json:"Commands"`
}

type CommandResponse struct {
	ID         uint   `json:"ID"`
	State      string `json:"State"`
	RawCommand string `json:"RawCommand"`
	ExitCode   int8   `json:"ExitCode"`
}

type ErrorResponse struct {
	Message string `json:"Message"`
	Status  uint   `json:"Status"`
}

// swagger:model jobSpec
type JobSpec struct {
	// label
	// required: true
	Label string `json:"Label"`
	// tasks
	// required: true
	Tasks []TaskSpec `json:"Tasks"`
}

type TaskSpec struct {
	ID       string            `json:"ID"`
	Config   map[string]string `json:"Config"`
	Commands []string          `json:"Commands"`
	Metadata map[string]string `json:"Metadata"`
}

// swagger:model GenericIdResponse
type GenericIdResponse struct {
	// Id
	// required
	Id string `json:"ID"`
}

var (
	ProcReqErr   = errors.New("error while trying to process response")
	EncodeResErr = errors.New("error while trying encode response")
)

func (a *HttpApi) CreateQueue(w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/queues/ createQueue
	//
	// Creates a queue
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   description: The queue payload
	//   required: true
	//   schema:
	//       "$ref": "#/definitions/Queue"
	// responses:
	//   '201':
	//     description: The queue ID
	//     schema:
	//       "$ref": "#/definitions/GenericIdResponse"
	var queue storage.Queue
	err := json.NewDecoder(r.Body).Decode(&queue)

	if err != nil {
		Write(w, http.StatusBadRequest, ErrorResponse{
			Message: "Maybe the body has a wrong shape",
			Status:  http.StatusBadRequest,
		})
	}

	if queue.ID == 0 {
		Write(w, http.StatusBadRequest, ErrorResponse{
			Message: "The queue ID can not be 0",
			Status:  http.StatusBadRequest,
		})
	}

	err = a.storage.SaveQueue(&queue)

	if err != nil {
		Write(w, http.StatusInternalServerError, ErrorResponse{
			Message: "Error while trying to save the new queue",
			Status:  http.StatusInternalServerError,
		})
	} else {
		super := a.arrebol.HireSupervisor(&queue)

		go super.Start()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"ID": "%d"}`, queue.ID)
	}
}

func (a *HttpApi) RetrieveQueue(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/queues/{queue_id} getQueue
	//
	// Retrieve queue by its id
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: The queue id
	//   required: true
	//   type: string
	// responses:
	//   '201':
	//     description: The queue
	//     schema:
	//       "$ref": "#/definitions/QueueResponse"
	params := mux.Vars(r)

	queueIDStr := params["qid"]
	queueID, err := strconv.Atoi(queueIDStr)

	if err != nil {
		Write(w, http.StatusBadRequest, ErrorResponse{
			Message: "Malformed request",
			Status:  http.StatusBadRequest,
		})
	} else {

		queue, err := a.storage.RetrieveQueue(uint(queueID))

		if err != nil {
			Write(w, http.StatusNotFound, ErrorResponse{
				Message: fmt.Sprintf("Queue with ID %d not found", queueID),
				Status:  http.StatusNotFound,
			})
		} else {
			pendingTasks := a.storage.RetrieveTasksByState(queue.ID, storage.TaskPending)
			runningTasks := a.storage.RetrieveTasksByState(queue.ID, storage.TaskRunning)
			response := responseFromQueue(queue, uint(len(pendingTasks)), uint(len(runningTasks)), uint(len(queue.Workers)))

			Write(w, http.StatusOK, &response)
		}
	}
}

func (a *HttpApi) RetrieveQueues(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/queues/ getQueues
	//
	// Retrieve current queues
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// responses:
	//   '200':
	//     description: The current queues
	//     schema:
	//       type: array
	//       items:
	//         "$ref": "#/definitions/QueueResponse"
	var response []*QueueResponse

	queues, err := a.storage.RetrieveQueues()

	if err != nil {
		Write(w, http.StatusNotFound, ErrorResponse{
			Message: fmt.Sprintf("%v", err),
			Status:  http.StatusNotFound,
		})
	} else {

		for _, queue := range queues {
			pendingTasks := a.storage.RetrieveTasksByState(queue.ID, storage.TaskPending)
			runningTasks := a.storage.RetrieveTasksByState(queue.ID, storage.TaskRunning)
			workers, _ := a.storage.RetrieveWorkersByQueueID(queue.ID)
			curQueue := responseFromQueue(queue, uint(len(pendingTasks)), uint(len(runningTasks)), uint(len(workers)))
			response = append(response, curQueue)
		}
		Write(w, http.StatusOK, response)
	}
}

func (a *HttpApi) CreateJob(w http.ResponseWriter, r *http.Request) {
	// swagger:operation POST /v1/queues/{queue_id}/jobs createJob
	//
	// Create a job
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: The queue id
	//   required: true
	//   type: string
	// - name: body
	//   in: body
	//   description: The job payload
	//   required: true
	//   schema:
	//       "$ref": "#/definitions/jobSpec"
	// responses:
	//   '201':
	//     description: The job id
	//     schema:
	//       "$ref": "#/definitions/GenericIdResponse"
	var jobSpec JobSpec
	params := mux.Vars(r)

	queueIDStr := params["qid"]

	err := json.NewDecoder(r.Body).Decode(&jobSpec)

	if err != nil {
		log.Println(ProcReqErr)
	}

	job := extractFromSpec(jobSpec)

	queueID, _ := strconv.Atoi(queueIDStr)
	queue, err := a.storage.RetrieveQueue(uint(queueID))

	if err != nil {
		Write(w, http.StatusInternalServerError, ErrorResponse{
			Message: err.Error(),
			Status:  http.StatusInternalServerError,
		})
	} else {
		queue.Jobs = append(queue.Jobs, job)
		err = a.storage.SaveQueue(queue)
		if err != nil {
			Write(w, http.StatusInternalServerError, ErrorResponse{
				Message: err.Error(),
				Status:  http.StatusInternalServerError,
			})
		}

		a.arrebol.AcceptJob(job)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"ID": "%d"}`, job.ID)
	}
}

func (a *HttpApi) RetrieveJobsByQueue(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/queues/{queue_id}/jobs retrieveJobsByQueue
	//
	// Retrieve jobs by queue
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: The queue id
	//   required: true
	//   type: string
	// responses:
	//   '200':
	//     description: The jobs
	//     schema:
	//       type: array
	//       items:
	//         "$ref": "#/definitions/Job"
	params := mux.Vars(r)

	queueIDStr := params["qid"]
	queueID, _ := strconv.Atoi(queueIDStr)

	jobs, err := a.storage.RetrieveJobsByQueueID(uint(queueID))

	if err != nil {
		Write(w, http.StatusInternalServerError, ErrorResponse{
			Message: err.Error(),
			Status:  http.StatusInternalServerError,
		})
	} else {
		Write(w, http.StatusOK, newJobResponses(jobs))
	}
}

func (a *HttpApi) RetrieveJobByQueue(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/queues/{queue_id}/jobs/{job_id} retrieveJobByQueue
	//
	// Retrieve job by queue
	// ---
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: The queue id
	//   required: true
	//   type: string
	// - name: id
	//   in: path
	//   description: The job id
	//   required: true
	//   type: string
	// responses:
	//   '200':
	//     description: The jobs
	//     schema:
	//        "$ref": "#/definitions/Job"
	params := mux.Vars(r)

	queueIDStr := params["qid"]
	queueID, _ := strconv.Atoi(queueIDStr)
	jobIDStr := params["jid"]
	jobID, _ := strconv.Atoi(jobIDStr)

	job, err := a.storage.RetrieveJobByQueue(uint(jobID), uint(queueID))

	if err != nil {
		Write(w, http.StatusNotFound, ErrorResponse{
			Message: err.Error(),
			Status:  http.StatusNotFound,
		})
	} else {
		Write(w, http.StatusOK, newJobResponse(job))
	}
}

func (a *HttpApi) AddNode(w http.ResponseWriter, r *http.Request) {
	Write(w, http.StatusAccepted, `{"Message": "no support yet"}`)
}

func (a *HttpApi) RetrieveNode(w http.ResponseWriter, r *http.Request) {
	Write(w, http.StatusAccepted, `{"Message": "no support yet"}`)
}

func (a *HttpApi) RetrieveNodes(w http.ResponseWriter, r *http.Request) {
	Write(w, http.StatusAccepted, `{"Message": "no support yet"}`)
}

func (a *HttpApi) GetVersion(w http.ResponseWriter, r *http.Request) {
	// swagger:operation GET /v1/version getVersion
	//
	// Retrieve the system version
	// ---
	// consumes:
	// - application/json
	// produces:
	// - text/plain
	// responses:
	//   '200':
	//     description: The system version
	//     type: string
	Write(w, http.StatusOK, Version{Tag: os.Getenv("VERSION_TAG"), Name: os.Getenv("VERSION_NAME")})
}

func (a *HttpApi) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	publickey, err := ioutil.ReadFile(os.Getenv("ARREBOL_PUB_KEY_PATH"))
	if err != nil {
		Write(w, http.StatusInternalServerError, ErrorResponse{
			Message: "Error while trying to get arrebol public key",
			Status:  http.StatusInternalServerError,
		})
	}
	_, err = w.Write(publickey)
	if err != nil {
		Write(w, http.StatusInternalServerError, ErrorResponse{
			Message: "Error while trying to get arrebol public key",
			Status:  http.StatusInternalServerError,
		})
	}
	w.WriteHeader(http.StatusOK)
}

func (a *HttpApi) Swagger(w http.ResponseWriter, r *http.Request) {
	fmt.Print("Get swagger received")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	gopath_cmd := exec.Command("/bin/sh", "-c", "echo $GOPATH")
	gopath, _ := gopath_cmd.Output()
	gopath_str := strings.TrimSpace(string(gopath))

	http.ServeFile(w, r, gopath_str+"/src/github.com/emanueljoivo/arrebol/api/swagger.json")
}

func Write(w http.ResponseWriter, statusCode int, i interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(i); err != nil {
		log.Println(EncodeResErr)
	}
}

func newJobResponses(jobs []*storage.Job) []JobResponse {
	var jr []JobResponse
	for _, job := range jobs {
		jr = append(jr, *newJobResponse(job))
	}
	return jr
}

func newJobResponse(job *storage.Job) *JobResponse {
	tsr := newTasksResponse(job.Tasks)
	return &JobResponse{
		ID:        job.ID,
		Label:     job.Label,
		State:     job.State.String(),
		CreatedAt: job.CreatedAt,
		UpdatedAt: job.UpdatedAt,
		Tasks:     tsr,
	}
}

func newTasksResponse(tasks []*storage.Task) []*TaskResponse {
	var tsr []*TaskResponse
	for _, task := range tasks {
		commandsResponse := newCommandResponse(task.Commands)
		tsr = append(tsr, &TaskResponse{
			ID:       task.ID,
			State:    task.State.String(),
			Commands: commandsResponse,
		})
	}
	return tsr
}

func newCommandResponse(commands []*storage.Command) []*CommandResponse {
	var cr []*CommandResponse
	for _, cmd := range commands {
		cr = append(cr, &CommandResponse{
			ID:         cmd.ID,
			State:      cmd.State.String(),
			RawCommand: cmd.RawCommand,
			ExitCode:   cmd.ExitCode,
		})
	}
	return cr
}

func responseFromQueue(queue *storage.Queue, pendingTasks uint, runningTasks uint, workers uint) *QueueResponse {
	return &QueueResponse{
		ID:           queue.ID,
		Name:         queue.Name,
		PendingTasks: pendingTasks,
		RunningTasks: runningTasks,
		Nodes:        uint(len(queue.Nodes)),
		Workers:      workers,
	}
}

func extractFromSpec(spec JobSpec) *storage.Job {
	var tasks []*storage.Task

	for _, taskSpec := range spec.Tasks {
		configs := extractConfigs(&taskSpec)
		metadata := extractMetadata(&taskSpec)
		commands := extractCommands(&taskSpec)

		tasks = append(tasks, &storage.Task{
			Config:   configs,
			State:    storage.TaskPending,
			Metadata: metadata,
			Commands: commands,
		})
	}
	return &storage.Job{
		Label: spec.Label,
		Tasks: tasks,
	}
}

func extractCommands(spec *TaskSpec) []*storage.Command {
	var commands []*storage.Command
	for _, cmd := range spec.Commands {
		commands = append(commands, &storage.Command{
			ExitCode:   -1,
			RawCommand: cmd,
			State:      storage.CmdNotStarted,
		})
	}
	return commands
}

func extractMetadata(spec *TaskSpec) []storage.TaskMetadata {
	var metadata []storage.TaskMetadata
	for k, v := range spec.Metadata {
		metadata = append(metadata, storage.TaskMetadata{
			Key:   k,
			Value: v,
		})
	}
	return metadata
}

func extractConfigs(task *TaskSpec) []storage.TaskConfig {
	var configs []storage.TaskConfig
	for k, v := range task.Config {
		configs = append(configs, storage.TaskConfig{
			Key:   k,
			Value: v,
		})
	}

	return configs
}
