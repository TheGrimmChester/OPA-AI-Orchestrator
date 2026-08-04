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

type githubProjectV2Meta struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	URL    string `json:"url,omitempty"`
	Number int    `json:"number,omitempty"`
}

func githubListProjectsV2(conn *opaConnector, owner string) ([]githubProjectV2Meta, error) {
	if githubUseMockAPI(conn) {
		return []githubProjectV2Meta{{
			ID: "PVT_mock1", Title: "Mock Project", URL: "https://github.com/orgs/" + owner + "/projects/1", Number: 1,
		}}, nil
	}
	// Prefer organization projects; fall back to user.
	data, err := githubGraphQL(conn, `
query($login:String!) {
  organization(login:$login) {
    projectsV2(first:40) { nodes { id title number url } }
  }
}`, map[string]interface{}{"login": owner})
	nodes := extractProjectsV2Nodes(data, "organization")
	if err != nil || len(nodes) == 0 {
		data2, err2 := githubGraphQL(conn, `
query($login:String!) {
  user(login:$login) {
    projectsV2(first:40) { nodes { id title number url } }
  }
}`, map[string]interface{}{"login": owner})
		if err2 != nil && err != nil {
			return nil, err
		}
		if err2 == nil {
			nodes = extractProjectsV2Nodes(data2, "user")
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	out := make([]githubProjectV2Meta, 0, len(nodes))
	for _, n := range nodes {
		m, _ := n.(map[string]interface{})
		if m == nil {
			continue
		}
		out = append(out, githubProjectV2Meta{
			ID: strFromAny(m["id"]), Title: strFromAny(m["title"]),
			URL: strFromAny(m["url"]), Number: intFromAny(m["number"]),
		})
	}
	return out, nil
}

func extractProjectsV2Nodes(data map[string]interface{}, key string) []interface{} {
	if data == nil {
		return nil
	}
	root, _ := data[key].(map[string]interface{})
	if root == nil {
		return nil
	}
	pv, _ := root["projectsV2"].(map[string]interface{})
	if pv == nil {
		return nil
	}
	nodes, _ := pv["nodes"].([]interface{})
	return nodes
}

// githubAddProjectV2DraftIssue creates a draft issue item on a Projects v2 board.
func githubAddProjectV2DraftIssue(conn *opaConnector, projectID, title, body string) (string, error) {
	if githubUseMockAPI(conn) {
		return "PVTI_mock_item", nil
	}
	data, err := githubGraphQL(conn, `
mutation($projectId:ID!, $title:String!, $body:String) {
  addProjectV2DraftIssue(input:{projectId:$projectId, title:$title, body:$body}) {
    projectItem { id }
  }
}`, map[string]interface{}{"projectId": projectID, "title": title, "body": body})
	if err != nil {
		return "", err
	}
	if add, ok := data["addProjectV2DraftIssue"].(map[string]interface{}); ok {
		if item, ok := add["projectItem"].(map[string]interface{}); ok {
			id := strFromAny(item["id"])
			if id != "" {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("addProjectV2DraftIssue returned no item id")
}

func githubUpdateProjectV2DraftIssue(conn *opaConnector, itemID, title, body string) error {
	// Draft issue title updates require the draftIssue content id, which callers may not have.
	// Item create path is the primary sync; title refresh is best-effort no-op for now.
	_ = conn
	_ = itemID
	_ = title
	_ = body
	return nil
}

// githubSetProjectV2ItemStatus maps an OPM column hint onto a Project "Status" single-select option.
func githubSetProjectV2ItemStatus(conn *opaConnector, projectID, itemID, statusHint string) error {
	if githubUseMockAPI(conn) {
		return nil
	}
	fieldID, options, err := githubProjectV2StatusField(conn, projectID)
	if err != nil {
		return err
	}
	optionID := matchStatusOption(options, statusHint)
	if optionID == "" {
		return fmt.Errorf("no Status option matched hint %q (have %d options)", statusHint, len(options))
	}
	_, err = githubGraphQL(conn, `
mutation($projectId:ID!, $itemId:ID!, $fieldId:ID!, $optionId:String!) {
  updateProjectV2ItemFieldValue(input:{
    projectId:$projectId, itemId:$itemId, fieldId:$fieldId,
    value:{ singleSelectOptionId:$optionId }
  }) { projectV2Item { id } }
}`, map[string]interface{}{
		"projectId": projectID, "itemId": itemID, "fieldId": fieldID, "optionId": optionID,
	})
	return err
}

func githubProjectV2StatusField(conn *opaConnector, projectID string) (fieldID string, options []map[string]string, err error) {
	data, err := githubGraphQL(conn, `
query($id:ID!) {
  node(id:$id) {
    ... on ProjectV2 {
      fields(first:40) {
        nodes {
          ... on ProjectV2SingleSelectField {
            id name
            options { id name }
          }
        }
      }
    }
  }
}`, map[string]interface{}{"id": projectID})
	if err != nil {
		return "", nil, err
	}
	node, _ := data["node"].(map[string]interface{})
	if node == nil {
		return "", nil, fmt.Errorf("project node missing")
	}
	fields, _ := node["fields"].(map[string]interface{})
	nodes, _ := fields["nodes"].([]interface{})
	for _, n := range nodes {
		m, _ := n.(map[string]interface{})
		if m == nil {
			continue
		}
		name := strings.ToLower(strFromAny(m["name"]))
		if name != "status" {
			continue
		}
		fieldID = strFromAny(m["id"])
		rawOpts, _ := m["options"].([]interface{})
		for _, o := range rawOpts {
			om, _ := o.(map[string]interface{})
			if om == nil {
				continue
			}
			options = append(options, map[string]string{
				"id": strFromAny(om["id"]), "name": strFromAny(om["name"]),
			})
		}
		if fieldID != "" {
			return fieldID, options, nil
		}
	}
	return "", nil, fmt.Errorf("no Status single-select field on project")
}

func matchStatusOption(options []map[string]string, hint string) string {
	hint = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(hint, "_", " ")))
	aliases := map[string][]string{
		"backlog":      {"backlog", "todo", "to do", "new"},
		"queue":        {"queue", "ready", "ready for work", "up next"},
		"in progress":  {"in progress", "in_progress", "doing", "active"},
		"review":       {"review", "in review", "code review"},
		"human review": {"human review", "human_review", "needs review", "waiting"},
		"done":         {"done", "complete", "completed", "closed", "finished"},
	}
	wanted := aliases[hint]
	if wanted == nil {
		wanted = []string{hint}
	}
	for _, w := range wanted {
		for _, o := range options {
			if strings.EqualFold(strings.TrimSpace(o["name"]), w) {
				return o["id"]
			}
		}
	}
	// Fuzzy contains
	for _, w := range wanted {
		for _, o := range options {
			n := strings.ToLower(o["name"])
			if strings.Contains(n, w) || strings.Contains(w, n) {
				return o["id"]
			}
		}
	}
	return ""
}
