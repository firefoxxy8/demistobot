package web

import (
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
)

func (ac *AppContext) logHandler(w http.ResponseWriter, r *http.Request) {
	fromStr := r.FormValue("from")
	toStr := r.FormValue("to")

	from := time.Time{}
	to := time.Time{}

	var err error
	if fromStr != "" {
		from, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			WriteError(w, ErrBadRequest)
		}
	}
	if toStr != "" {
		to, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			WriteError(w, ErrBadRequest)
		}
	}
	oauths, err := ac.r.OAuths(from, to)
	if err != nil {
		logrus.WithError(err).Errorln("Unable to access history")
		WriteError(w, ErrInternalServer)
	}
	writeJSON(w, oauths)
}
