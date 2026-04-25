package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpa-control-center/internal/backend"
)

type Options struct {
	AuthUsername string
	AuthPassword string
}

type Server struct {
	service *backend.Backend
	hub     *eventHub
	dataDir string
	static  fs.FS

	authUsername string
	authPassword string
}

type exportResponse struct {
	backend.ExportResult
	DownloadURL string `json:"downloadUrl,omitempty"`
}

type boolRequest struct {
	Disabled bool `json:"disabled"`
}

type namesRequest struct {
	Names []string `json:"names"`
}

type recentLogsResponse struct {
	Items []backend.LogEntry `json:"items"`
}

type eventEnvelope struct {
	name string
	data []byte
}

type eventHub struct {
	mu          sync.Mutex
	nextID      int
	subscribers map[int]chan eventEnvelope
}

func newEventHub() *eventHub {
	return &eventHub{
		subscribers: make(map[int]chan eventEnvelope),
	}
}

func (h *eventHub) Emit(event string, payload any) {
	if h == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		data, _ = json.Marshal(map[string]string{"error": err.Error()})
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for id, subscriber := range h.subscribers {
		select {
		case subscriber <- eventEnvelope{name: event, data: data}:
		default:
			close(subscriber)
			delete(h.subscribers, id)
		}
	}
}

func (h *eventHub) subscribe() (int, <-chan eventEnvelope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.nextID++
	ch := make(chan eventEnvelope, 128)
	h.subscribers[h.nextID] = ch
	return h.nextID, ch
}

func (h *eventHub) unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.subscribers[id]
	if !ok {
		return
	}
	delete(h.subscribers, id)
	close(ch)
}

func New(dataDir string, assets fs.FS, options Options) (*Server, error) {
	staticFS, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		return nil, err
	}

	hub := newEventHub()
	service, err := backend.New(dataDir, hub)
	if err != nil {
		return nil, err
	}

	return &Server{
		service:      service,
		hub:          hub,
		dataDir:      dataDir,
		static:       staticFS,
		authUsername: strings.TrimSpace(options.AuthUsername),
		authPassword: strings.TrimSpace(options.AuthPassword),
	}, nil
}

func (s *Server) Close() error {
	if s == nil || s.service == nil {
		return nil
	}
	return s.service.Close()
}

func (s *Server) Handler() http.Handler {
	protected := http.NewServeMux()
	protected.HandleFunc("GET /api/events", s.handleEvents)
	protected.HandleFunc("GET /api/settings", s.handleGetSettings)
	protected.HandleFunc("POST /api/settings", s.handleSaveSettings)
	protected.HandleFunc("POST /api/settings/test", s.handleTestSettings)
	protected.HandleFunc("POST /api/settings/test-save", s.handleTestAndSaveSettings)
	protected.HandleFunc("GET /api/scheduler/status", s.handleGetSchedulerStatus)
	protected.HandleFunc("GET /api/dashboard", s.handleGetDashboard)
	protected.HandleFunc("GET /api/accounts", s.handleListAccountsPage)
	protected.HandleFunc("POST /api/inventory/sync", s.handleSyncInventory)
	protected.HandleFunc("POST /api/tasks/scan", s.handleRunScan)
	protected.HandleFunc("POST /api/tasks/cancel", s.handleCancelTask)
	protected.HandleFunc("POST /api/tasks/maintain", s.handleRunMaintain)
	protected.HandleFunc("GET /api/quotas", s.handleGetQuotas)
	protected.HandleFunc("POST /api/accounts/{name}/probe", s.handleProbeAccount)
	protected.HandleFunc("POST /api/accounts/bulk/probe", s.handleProbeAccounts)
	protected.HandleFunc("POST /api/accounts/{name}/disabled", s.handleSetAccountDisabled)
	protected.HandleFunc("POST /api/accounts/bulk/disabled", s.handleSetAccountsDisabled)
	protected.HandleFunc("DELETE /api/accounts/{name}", s.handleDeleteAccount)
	protected.HandleFunc("POST /api/accounts/bulk/delete", s.handleDeleteAccounts)
	protected.HandleFunc("POST /api/exports", s.handleExportAccounts)
	protected.HandleFunc("GET /api/exports/download/{name}", s.handleDownloadExport)
	protected.HandleFunc("GET /api/scan-runs/{runID}", s.handleGetScanDetailsPage)
	protected.HandleFunc("GET /api/logs/recent", s.handleRecentLogs)
	protected.HandleFunc("/", s.handleApp)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.Handle("/", s.withAuth(protected))
	return root
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	if s.authPassword == "" {
		return next
	}

	username := s.authUsername
	if username == "" {
		username = "admin"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != username || pass != s.authPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="CPA Control Center"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	id, events := s.hub.subscribe()
	defer s.hub.unsubscribe(id)

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\n", event.name)
			fmt.Fprintf(w, "data: %s\n\n", event.data)
			flusher.Flush()
		}
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	settings, err := s.service.GetSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var input backend.AppSettings
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, err := s.service.SaveSettings(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleTestSettings(w http.ResponseWriter, r *http.Request) {
	var input backend.AppSettings
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.TestConnection(input)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTestAndSaveSettings(w http.ResponseWriter, r *http.Request) {
	var input backend.AppSettings
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.TestAndSaveSettings(input)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetSchedulerStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.service.GetSchedulerStatus())
}

func (s *Server) handleGetDashboard(w http.ResponseWriter, _ *http.Request) {
	snapshot, err := s.service.GetDashboardSnapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleListAccountsPage(w http.ResponseWriter, r *http.Request) {
	filter := backend.AccountFilter{
		Query:    strings.TrimSpace(r.URL.Query().Get("query")),
		State:    strings.TrimSpace(r.URL.Query().Get("state")),
		Provider: strings.TrimSpace(r.URL.Query().Get("provider")),
		Type:     strings.TrimSpace(r.URL.Query().Get("type")),
		PlanType: strings.TrimSpace(r.URL.Query().Get("planType")),
	}
	if rawDisabled := strings.TrimSpace(r.URL.Query().Get("disabled")); rawDisabled != "" {
		value, err := strconv.ParseBool(rawDisabled)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid disabled filter: %w", err))
			return
		}
		filter.Disabled = &value
	}

	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 20)
	result, err := s.service.ListAccountsPage(filter, page, pageSize)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSyncInventory(w http.ResponseWriter, _ *http.Request) {
	result, err := s.service.SyncInventory()
	if err != nil {
		writeError(w, statusFromTaskError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRunScan(w http.ResponseWriter, _ *http.Request) {
	result, err := s.service.RunScan()
	if err != nil {
		writeError(w, statusFromTaskError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCancelTask(w http.ResponseWriter, _ *http.Request) {
	cancelled, err := s.service.CancelScan()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": cancelled})
}

func (s *Server) handleRunMaintain(w http.ResponseWriter, r *http.Request) {
	var input backend.MaintainOptions
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.RunMaintain(input)
	if err != nil {
		writeError(w, statusFromTaskError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetQuotas(w http.ResponseWriter, _ *http.Request) {
	result, err := s.service.GetCodexQuotaSnapshot()
	if err != nil {
		writeError(w, statusFromTaskError(err), err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleProbeAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	result, err := s.service.ProbeAccount(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleProbeAccounts(w http.ResponseWriter, r *http.Request) {
	var input namesRequest
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.ProbeAccounts(input.Names)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSetAccountDisabled(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	var input boolRequest
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.SetAccountDisabled(name, input.Disabled)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSetAccountsDisabled(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Names    []string `json:"names"`
		Disabled bool     `json:"disabled"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.SetAccountsDisabled(input.Names, input.Disabled)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PathValue("name"))
	result, err := s.service.DeleteAccount(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDeleteAccounts(w http.ResponseWriter, r *http.Request) {
	var input namesRequest
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.DeleteAccounts(input.Names)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleExportAccounts(w http.ResponseWriter, r *http.Request) {
	var input backend.ExportRequest
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.service.ExportAccounts(input.Kind, input.Format, input.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	response := exportResponse{ExportResult: result}
	if strings.TrimSpace(result.Path) != "" {
		fileName := filepath.Base(result.Path)
		response.DownloadURL = "/api/exports/download/" + path.Base(fileName)
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleDownloadExport(w http.ResponseWriter, r *http.Request) {
	fileName := strings.TrimSpace(r.PathValue("name"))
	if fileName == "" || path.Base(fileName) != fileName {
		writeError(w, http.StatusBadRequest, errors.New("invalid export file"))
		return
	}
	fullPath := filepath.Join(s.dataDir, "exports", fileName)
	info, err := os.Stat(fullPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, errors.New("export file not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if info.IsDir() {
		writeError(w, http.StatusBadRequest, errors.New("invalid export file"))
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileName))
	http.ServeFile(w, r, fullPath)
}

func (s *Server) handleGetScanDetailsPage(w http.ResponseWriter, r *http.Request) {
	runID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("runID")), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid run id: %w", err))
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "pageSize", 20)
	result, err := s.service.GetScanDetailsPage(runID, page, pageSize)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRecentLogs(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 200)
	items, err := readRecentLogs(filepath.Join(s.dataDir, "app.log"), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, recentLogsResponse{Items: items})
}

func (s *Server) handleApp(w http.ResponseWriter, r *http.Request) {
	requestPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if requestPath == "." {
		requestPath = ""
	}
	if strings.HasPrefix(requestPath, "api/") {
		writeError(w, http.StatusNotFound, errors.New("not found"))
		return
	}

	target := "index.html"
	if requestPath != "" {
		target = requestPath
	}

	if file, err := s.static.Open(target); err == nil {
		defer file.Close()
		if info, statErr := file.Stat(); statErr == nil && !info.IsDir() {
			http.FileServer(http.FS(s.static)).ServeHTTP(w, r)
			return
		}
	}
	if requestPath != "" && path.Ext(requestPath) != "" {
		writeError(w, http.StatusNotFound, errors.New("asset not found"))
		return
	}

	index, err := s.static.Open("index.html")
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("frontend assets not found"))
		return
	}
	defer index.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, index)
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{
		"error": strings.TrimSpace(err.Error()),
	})
}

func queryInt(r *http.Request, key string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func statusFromTaskError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	message := strings.TrimSpace(err.Error())
	lower := strings.ToLower(message)
	if strings.Contains(lower, "already running") || strings.Contains(message, "任务正在执行中") {
		return http.StatusConflict
	}
	return http.StatusBadGateway
}

func readRecentLogs(logPath string, limit int) ([]backend.LogEntry, error) {
	if limit <= 0 {
		limit = 200
	}
	file, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []backend.LogEntry{}, nil
		}
		return nil, err
	}
	defer file.Close()

	lines := make([]string, 0, limit)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) > limit {
			lines = lines[len(lines)-limit:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	items := make([]backend.LogEntry, 0, len(lines))
	for index := len(lines) - 1; index >= 0; index-- {
		parts := strings.SplitN(lines[index], " | ", 4)
		if len(parts) != 4 {
			continue
		}
		items = append(items, backend.LogEntry{
			Timestamp: parts[0],
			Kind:      parts[1],
			Level:     parts[2],
			Message:   parts[3],
		})
	}
	return items, nil
}

func Run(ctx context.Context, dataDir string, assets fs.FS, listenAddr string, options Options) error {
	server, err := New(dataDir, assets, options)
	if err != nil {
		return err
	}
	defer server.Close()

	httpServer := &http.Server{
		Addr:    listenAddr,
		Handler: server.Handler(),
	}

	errCh := make(chan error, 1)
	go func() {
		if serveErr := httpServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return <-errCh
	case serveErr := <-errCh:
		return serveErr
	}
}
