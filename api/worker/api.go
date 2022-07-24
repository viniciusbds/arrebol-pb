package worker

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/auth/authorizer/policy/allowlist"
	"github.com/ufcg-lsd/arrebol-pb/arrebol/manager"
	"github.com/ufcg-lsd/arrebol-pb/storage"
)

var (
	al allowlist.AllowList
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
		err              error
		signature        []byte
		encodedPublicKey string
		publicKey        []byte
		_payload         string
		_httpbody        HTTPBodyRM
	)

	if encodedPublicKey, err = GetHeader(r, PublicKeyHeader); err != nil {
		WriteBadRequest(&w, err.Error())
		return
	}

	if publicKey, err = base64.StdEncoding.DecodeString(encodedPublicKey); err != nil {
		WriteBadRequest(&w, err.Error())
		return
	}

	if err = json.NewDecoder(r.Body).Decode(&_httpbody); err != nil {
		WriteBadRequest(&w, WrongBodyMsg+": "+err.Error())
		return
	}
	_payload = _httpbody.Payload
	signature = _httpbody.Signature

	if _, err = a.auth.Authenticator.AuthenticateRM(string(publicKey), signature, _payload); err != nil {
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
