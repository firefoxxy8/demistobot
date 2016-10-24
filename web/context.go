package web

import (
	"sync"
	"time"

	"github.com/demisto/demistobot/repo"
)

// AppContext holds the web context for the handlers
type AppContext struct {
	r      *repo.Repo
	mux    sync.Mutex
	states map[string]time.Time
	stop   chan bool
}

// NewContext creates a new context
func NewContext(r *repo.Repo) *AppContext {
	ac := &AppContext{r: r, states: make(map[string]time.Time), stop: make(chan bool, 1)}
	go ac.cleanStates()
	return ac
}

func (ac *AppContext) addState(state string) {
	ac.mux.Lock()
	defer ac.mux.Unlock()

	ac.states[state] = time.Now()
}

// state retrieval
func (ac *AppContext) state(state string) (time.Time, bool) {
	ac.mux.Lock()
	defer ac.mux.Unlock()

	t, ok := ac.states[state]
	return t, ok
}

// state retrieval
func (ac *AppContext) removeState(state string) {
	ac.mux.Lock()
	defer ac.mux.Unlock()

	delete(ac.states, state)
}

// doClean the states of old stuff
func (ac *AppContext) doClean() {
	ac.mux.Lock()
	defer ac.mux.Unlock()
	var d []string

	cutoff := time.Now().Add(-10 * time.Minute)
	for k, v := range ac.states {
		if v.Before(cutoff) {
			d = append(d, k)
		}
	}
	for _, s := range d {
		delete(ac.states, s)
	}
}

// cleanStates should be called from a separate Go routine as it is not returning
func (ac *AppContext) cleanStates() {
	t := time.NewTimer(10 * time.Minute)
	for {
		select {
		case <-t.C:
			ac.doClean()
		case <-ac.stop:
			t.Stop()
			return
		}
	}
	return
}

// stopCleaning when it's time to stop the router
func (ac *AppContext) Close() error {
	ac.stop <- true
	return nil
}
