package main

import (
	"sync"
)

// Per-kind semaphores so security and bugbot can run in parallel without
// exhausting the global scmProcessSem alone.
var (
	kindSemOnce sync.Once
	kindSems    map[agentKind]chan struct{}
)

func kindConcurrency(k agentKind) int {
	switch k {
	case kindPrepare:
		return 2
	case kindSecurity, kindBugbot, kindCheckup:
		return clampInt(scmProcessConcurrency(), 1, 4)
	case kindApproval, kindCloud:
		return 2
	default:
		return 1
	}
}

func ensureKindSems() {
	kindSemOnce.Do(func() {
		kindSems = map[agentKind]chan struct{}{
			kindPrepare:  make(chan struct{}, kindConcurrency(kindPrepare)),
			kindSecurity: make(chan struct{}, kindConcurrency(kindSecurity)),
			kindBugbot:   make(chan struct{}, kindConcurrency(kindBugbot)),
			kindCheckup:  make(chan struct{}, kindConcurrency(kindCheckup)),
			kindApproval: make(chan struct{}, kindConcurrency(kindApproval)),
			kindCloud:    make(chan struct{}, kindConcurrency(kindCloud)),
		}
	})
}

func acquireKindSlot(k agentKind) {
	ensureKindSems()
	ch, ok := kindSems[k]
	if !ok {
		acquireSCMProcessSlot()
		return
	}
	ch <- struct{}{}
}

func releaseKindSlot(k agentKind) {
	ensureKindSems()
	ch, ok := kindSems[k]
	if !ok {
		releaseSCMProcessSlot()
		return
	}
	<-ch
}
