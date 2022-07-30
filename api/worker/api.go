package worker

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/authorizer/policy/allowlist"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/key"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/manager"
	"github.com/ufcg-lsd/arrebol-pb/storage"
)

var (
	al allowlist.AllowList
)

const (
	RESOURCE_MANAGER_KEY_NAME               = "resource-manager"
	RESOURCE_MANAGER_AUTHENTICATION_MESSAGE = "RESOURCE_MANAGER_AUTHENTICATION_MESSAGE"
)

type API struct {
	server  *http.Server
	manager manager.Manager
	auth    *auth.Auth
	storage *storage.Storage
}

func New(storage *storage.Storage) *API {
	return &API{
		storage: storage,
		auth:    auth.NewAuth(),
		manager: *manager.NewManager(storage),
	}
}

func (a *API) Start(port string) error {
	a.server = &http.Server{
		Addr:    ":" + port,
		Handler: a.bootRouter(),
	}
	log.Println("Starting worker api")
	return a.server.ListenAndServe()
}

func (a *API) bootRouter() *mux.Router {
	router := mux.NewRouter()

	al = allowlist.NewAllowList()

	router.HandleFunc("/v1/workers", a.AddWorker).Methods(http.MethodPost)
	router.HandleFunc("/v1/workers/publicKey", a.AddPublicKey).Methods(http.MethodPost)
	router.HandleFunc("/v1/workers/id", a.GetAvailableWorkerID).Methods(http.MethodPost)

	router.HandleFunc("/v1/workers/{wid}/queues/{qid}/tasks", a.GetTask).Methods(http.MethodGet)
	router.HandleFunc("/v1/workers/{wid}/queues/{qid}/tasks", a.ReportTask).Methods(http.MethodPut)

	return router
}

func (a *API) AddPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
}

func (a *API) GetAvailableWorkerID(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		signature []byte
		message   string
		_httpbody HTTPBodyRM
	)

	publicKey, err := key.GetPublicKey(RESOURCE_MANAGER_KEY_NAME)
	if err != nil {
		WriteBadRequest(&w, WrongBodyMsg+": "+err.Error())
		return
	}

	if err = json.NewDecoder(r.Body).Decode(&_httpbody); err != nil {
		WriteBadRequest(&w, WrongBodyMsg+": "+err.Error())
		return
	}
	signature = _httpbody.Signature

	message = os.Getenv(RESOURCE_MANAGER_AUTHENTICATION_MESSAGE)

	if _, err = a.auth.Authenticator.AuthenticateRM(publicKey, signature, message); err != nil {
		log.Println("Unauthorized: " + r.RemoteAddr + " - " + err.Error())
		WriteBadRequest(&w, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json, err := json.Marshal(map[string]string{"worker-id": al.GetNextAvailableWorkerID()})
	if err != nil {
		log.Fatalf("Error happened in JSON marshal. Err: %s", err)
	}
	w.Write(json)
}

func (a *API) GetTask(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
}

func (a *API) ReportTask(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
}
