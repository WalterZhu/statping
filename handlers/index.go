package handlers

import (
	"github.com/statping/statping/types/core"
	"github.com/statping/statping/types/services"
	"github.com/statping/statping/utils"
	"net/http"
)

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !core.App.Setup {
		ExecuteResponse(w, r, "index.html", core.App, "setup")
		return
	}
	ExecuteResponse(w, r, "index.html", core.App, nil)
}

func baseHandler(w http.ResponseWriter, r *http.Request) {
	ExecuteResponse(w, r, "index.html", core.App, nil)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"services": len(services.All()),
		"online":   true,
		"setup":    core.App.Setup,
		"start_at": utils.TimeFormat(core.App.Started),
		"uuid"    : core.App.UUID,
	}
	returnJson(health, w, r)
}
