package main

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	openclient "github.com/TheGrimmChester/open-client-go"
	openlogger "github.com/TheGrimmChester/open-logger-go"
)

const peerSCMEventsScope = "scm:events"

type peerCheckerDecl struct {
	ID           string `json:"id"`
	CheckRunName string `json:"check_run_name"`
	ShouldRun    bool   `json:"should_run"`
	Reason       string `json:"reason,omitempty"`
}

type peerSCMEventsResponse struct {
	Checkers []peerCheckerDecl `json:"checkers"`
}

type peerSCMTarget struct {
	Product string
	EnvVar  string
	Aud     string
}

var scmPeerTargets = []peerSCMTarget{
	{Product: "osa", EnvVar: "PEER_OSA_URL", Aud: "osa-api"},
	{Product: "opl", EnvVar: "PEER_OPL_URL", Aud: "opl-api"},
	{Product: "opm", EnvVar: "PEER_OPM_URL", Aud: "opm-api"},
}

func peerProductConfigured(envVar string) bool {
	return strings.TrimSpace(os.Getenv(envVar)) != ""
}

func fanOutSCMEventToPeers(ctx context.Context, env *scmEventEnvelope) map[string]peerSCMEventsResponse {
	out := map[string]peerSCMEventsResponse{}
	if env == nil {
		return out
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, target := range scmPeerTargets {
		if !peerProductConfigured(target.EnvVar) {
			continue
		}
		wg.Add(1)
		go func(t peerSCMTarget) {
			defer wg.Done()
			resp, err := postPeerSCMEvent(ctx, t, env)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				openlogger.LogWarn("peer scm events failed", map[string]interface{}{
					"product": t.Product, "error": err.Error(), "event_id": env.ID,
				})
				out[t.Product] = peerSCMEventsResponse{}
				return
			}
			out[t.Product] = resp
		}(target)
	}
	wg.Wait()
	return out
}

func postPeerSCMEvent(ctx context.Context, target peerSCMTarget, env *scmEventEnvelope) (peerSCMEventsResponse, error) {
	cfg := openclient.PeerFromEnv(target.EnvVar, "ora-api", target.Aud, peerSCMEventsScope)
	cfg.OrgID = env.OrganizationID
	var out peerSCMEventsResponse
	err := openclient.PeerJSON(ctx, cfg, http.MethodPost, "/api/peer/scm/events", env, &out)
	return out, err
}

type peerCheckerWithProduct struct {
	Product string
	peerCheckerDecl
}

func aggregatePeerCheckersWithProduct(responses map[string]peerSCMEventsResponse, checks []string) []peerCheckerWithProduct {
	allowed := map[string]struct{}{}
	for _, c := range checks {
		if strings.Contains(c, ":") {
			allowed[c] = struct{}{}
		}
	}
	var out []peerCheckerWithProduct
	for product, resp := range responses {
		for _, ch := range resp.Checkers {
			key := checkerStatusKey(product, ch.ID)
			if len(allowed) > 0 {
				if _, ok := allowed[key]; !ok {
					continue
				}
			}
			if ch.CheckRunName == "" {
				ch.CheckRunName = strings.ToUpper(product) + " / " + ch.ID
			}
			out = append(out, peerCheckerWithProduct{Product: product, peerCheckerDecl: ch})
		}
	}
	return out
}

func publishPeerCheckerStatuses(conn *opaConnector, env *scmEventEnvelope, checkers []peerCheckerWithProduct) map[string]int64 {
	if conn == nil || env == nil {
		return nil
	}
	owner, repo := splitOwnerRepo(env.RepoFullName)
	if owner == "" || repo == "" {
		return nil
	}
	ids := map[string]int64{}
	for _, item := range checkers {
		if !item.ShouldRun {
			continue
		}
		key := checkerStatusKey(item.Product, item.ID)
		meta := checkerPublishMeta{
			Key:        key,
			Name:       item.CheckRunName,
			SHA:        env.CommitSHA,
			Status:     "queued",
			Title:      item.CheckRunName,
			Summary:    nz(item.Reason, "Peer checker queued"),
			DetailsURL: scmJobDashboardURL(env.SCMJobID),
		}
		id, mode, err := publishCheckerResult(conn, owner, repo, meta)
		if err != nil {
			openlogger.LogWarn("publish peer checker status failed", map[string]interface{}{
				"checker": key, "error": err.Error(),
			})
			continue
		}
		if id != 0 {
			ids[key] = id
		}
		if mode != "" && env.SCMJobID != "" {
			if job := getSCMJob(env.SCMJobID); job != nil {
				if job.Summary == nil {
					job.Summary = map[string]interface{}{}
				}
				job.Summary["checker_publish_"+key] = mode
				persistSCMJob(job)
			}
		}
	}
	return ids
}

func dispatchSCMPeerCheckers(conn *opaConnector, env *scmEventEnvelope, checks []string) map[string]int64 {
	return dispatchSCMCheckers(conn, env, checks, nil)
}

// dispatchSCMCheckers evaluates native ORA checkers in-process, fans out to peer
// products, and publishes GitHub statuses for every checker that should_run.
func dispatchSCMCheckers(conn *opaConnector, env *scmEventEnvelope, checks []string, raw []byte) map[string]int64 {
	if env == nil || conn == nil {
		return nil
	}
	decls := evaluateORANativeCheckers(env, checks, raw)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	responses := fanOutSCMEventToPeers(ctx, env)
	decls = append(decls, aggregatePeerCheckersWithProduct(responses, checks)...)
	return publishPeerCheckerStatuses(conn, env, decls)
}
