package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Projects v2 (GraphQL) publish — only when roadmap_projects_v2 prefs is on
// and the installation granted organization_projects write.

func publishRoadmapProjectsV2(conn *opaConnector, owner, repoFull string, issues []map[string]interface{}) (map[string]interface{}, error) {
	out := map[string]interface{}{"enabled": true, "status": "skipped"}
	if conn == nil {
		out["status"] = "no_connector"
		return out, nil
	}
	health := assessInstallationPermHealth(conn)
	if !health.ProjectsOK && conn.Kind == "github_app" {
		out["status"] = "missing_organization_projects"
		out["missing"] = health.OptionalMissing
		return out, fmt.Errorf("installation lacks organization_projects write")
	}
	if githubUseMockAPI(conn) {
		out["status"] = "mock"
		out["project_title"] = "OPA Roadmap (mock)"
		out["items"] = len(issues)
		return out, nil
	}

	title := "OPA Roadmap — " + repoFull
	projectID, err := githubEnsureOrgProjectV2(conn, owner, title)
	if err != nil {
		out["status"] = "error"
		out["error"] = err.Error()
		return out, err
	}
	out["project_id"] = projectID
	out["project_title"] = title
	linked := 0
	for _, iss := range issues {
		num := intFromAny(iss["number"])
		if num <= 0 {
			continue
		}
		nodeID, err := githubIssueNodeID(conn, owner, strings.TrimPrefix(repoFull, owner+"/"), num)
		if err != nil {
			continue
		}
		if err := githubAddProjectV2Item(conn, projectID, nodeID); err == nil {
			linked++
		}
	}
	out["status"] = "ok"
	out["items"] = linked
	return out, nil
}

func githubGraphQL(conn *opaConnector, query string, variables map[string]interface{}) (map[string]interface{}, error) {
	tok, err := githubAccessToken(conn)
	if err != nil {
		return nil, err
	}
	if conn.Kind == "github_app" && conn.InstallationID != "" {
		if t3, e3 := githubInstallationToken(conn.InstallationID); e3 == nil {
			tok = t3
		}
	}
	payload, _ := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	req, err := http.NewRequest(http.MethodPost, "https://api.github.com/graphql", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := githubHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graphql %d: %s", resp.StatusCode, truncateStr(string(raw), 300))
	}
	var out struct {
		Data   map[string]interface{} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if len(out.Errors) > 0 {
		return out.Data, fmt.Errorf("graphql: %s", out.Errors[0].Message)
	}
	return out.Data, nil
}

func githubEnsureOrgProjectV2(conn *opaConnector, owner, title string) (string, error) {
	// Try find existing project by title (first page).
	data, err := githubGraphQL(conn, `
query($login:String!) {
  organization(login:$login) {
    projectsV2(first:20) { nodes { id title } }
  }
}`, map[string]interface{}{"login": owner})
	if err == nil {
		if org, ok := data["organization"].(map[string]interface{}); ok {
			if pv, ok := org["projectsV2"].(map[string]interface{}); ok {
				if nodes, ok := pv["nodes"].([]interface{}); ok {
					for _, n := range nodes {
						m, _ := n.(map[string]interface{})
						if m != nil && strings.EqualFold(strFromAny(m["title"]), title) {
							return strFromAny(m["id"]), nil
						}
					}
				}
			}
		}
	}
	oid, oerr := githubOrgNodeID(conn, owner)
	if oerr != nil {
		return "", oerr
	}
	data, err = githubGraphQL(conn, `
mutation($ownerId:ID!, $title:String!) {
  createProjectV2(input:{ownerId:$ownerId, title:$title}) {
    projectV2 { id }
  }
}`, map[string]interface{}{"ownerId": oid, "title": title})
	if err != nil {
		return "", err
	}
	if cp, ok := data["createProjectV2"].(map[string]interface{}); ok {
		if p, ok := cp["projectV2"].(map[string]interface{}); ok {
			id := strFromAny(p["id"])
			if id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("createProjectV2 returned no id")
}

func githubOrgNodeID(conn *opaConnector, login string) (string, error) {
	data, err := githubGraphQL(conn, `query($login:String!){ organization(login:$login){ id } }`,
		map[string]interface{}{"login": login})
	if err != nil {
		// User account fallback.
		data, err = githubGraphQL(conn, `query($login:String!){ user(login:$login){ id } }`,
			map[string]interface{}{"login": login})
		if err != nil {
			return "", err
		}
		if u, ok := data["user"].(map[string]interface{}); ok {
			return strFromAny(u["id"]), nil
		}
		return "", fmt.Errorf("no user id for %s", login)
	}
	if org, ok := data["organization"].(map[string]interface{}); ok {
		id := strFromAny(org["id"])
		if id != "" {
			return id, nil
		}
	}
	return "", fmt.Errorf("no organization id for %s", login)
}

func githubIssueNodeID(conn *opaConnector, owner, repo string, number int) (string, error) {
	data, err := githubGraphQL(conn, `
query($owner:String!,$repo:String!,$n:Int!){
  repository(owner:$owner,name:$repo){ issue(number:$n){ id } }
}`, map[string]interface{}{"owner": owner, "repo": repo, "n": number})
	if err != nil {
		return "", err
	}
	if r, ok := data["repository"].(map[string]interface{}); ok {
		if iss, ok := r["issue"].(map[string]interface{}); ok {
			return strFromAny(iss["id"]), nil
		}
	}
	return "", fmt.Errorf("issue node not found")
}

func githubAddProjectV2Item(conn *opaConnector, projectID, contentID string) error {
	_, err := githubGraphQL(conn, `
mutation($projectId:ID!, $contentId:ID!) {
  addProjectV2ItemById(input:{projectId:$projectId, contentId:$contentId}) {
    item { id }
  }
}`, map[string]interface{}{"projectId": projectID, "contentId": contentID})
	return err
}
