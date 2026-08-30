// Package isolate implements the "what actually triggers the block"
// diagnostic: given a URL that's currently getting a blocked response,
// it systematically removes one query parameter at a time and tries a
// battery of common WAF-evasion headers, one change at a time, and
// reports which single change flips the response from blocked to
// clean. This is the request-shape half of WAF bypass work — deciding
// which *encoding* gets a known payload through (Atlas's job, for SQLi
// specifically) is a different, later step once you know which
// component is actually responsible.
package isolate

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/Mohamed-Newish/sharingan-go/internal/stealth"
)

// Result is one mutation tried and what happened. Error is set instead
// of Status/Unblocked when the request itself never completed (e.g.
// the circuit breaker tripped) — never silently dropped, since a
// missing row would misleadingly read as "not tested" rather than
// "tried and failed."
type Result struct {
	Mutation  string
	Status    int
	Unblocked bool // true if this mutation's status is NOT in stealth.IsBlocked
	Error     string
}

// headerBattery is a fixed set of common WAF-evasion header tricks,
// tried one at a time (never combined — the whole point is isolating a
// single variable).
var headerBattery = []struct{ Name, Value string }{
	{"X-Forwarded-For", "127.0.0.1"},
	{"X-Originating-IP", "127.0.0.1"},
	{"X-Client-IP", "127.0.0.1"},
	{"X-Remote-IP", "127.0.0.1"},
	{"X-Custom-IP-Authorization", "127.0.0.1"},
	{"X-Forwarded-Host", ""}, // set to the request's own host, filled in at call time
	{"Referer", ""},          // "" here means: strip Referer entirely
}

// Run sends a baseline request to rawURL (with the given extra
// headers), and — only if that baseline is actually blocked — tries
// each mutation in turn, reporting which ones un-block it.
func Run(rawURL string, baseHeaders map[string]string, client *stealth.Client) ([]Result, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	baseStatus, err := send(rawURL, baseHeaders, client)
	if err != nil {
		return nil, fmt.Errorf("baseline request: %w", err)
	}
	results := []Result{{Mutation: "baseline", Status: baseStatus, Unblocked: !stealth.IsBlocked(baseStatus)}}
	if !stealth.IsBlocked(baseStatus) {
		return results, fmt.Errorf("baseline returned %d — not blocked, nothing to isolate", baseStatus)
	}

	// One query param removed at a time.
	q := u.Query()
	for key := range q {
		q2 := url.Values{}
		for k, v := range q {
			if k != key {
				q2[k] = v
			}
		}
		u2 := *u
		u2.RawQuery = q2.Encode()
		mutation := fmt.Sprintf("remove param %q", key)
		status, err := send(u2.String(), baseHeaders, client)
		if err != nil {
			results = append(results, Result{Mutation: mutation, Error: err.Error()})
			continue
		}
		results = append(results, Result{
			Mutation:  mutation,
			Status:    status,
			Unblocked: !stealth.IsBlocked(status),
		})
	}

	// One header trick at a time.
	for _, h := range headerBattery {
		merged := map[string]string{}
		for k, v := range baseHeaders {
			merged[k] = v
		}
		name, value := h.Name, h.Value
		switch {
		case name == "Referer" && value == "":
			delete(merged, "Referer")
		case name == "X-Forwarded-Host" && value == "":
			merged[name] = u.Host
		default:
			merged[name] = value
		}
		label := fmt.Sprintf("header %s: %s", name, merged[name])
		if name == "Referer" && merged["Referer"] == "" {
			label = "strip Referer"
		}
		status, err := send(rawURL, merged, client)
		if err != nil {
			results = append(results, Result{Mutation: label, Error: err.Error()})
			continue
		}
		results = append(results, Result{Mutation: label, Status: status, Unblocked: !stealth.IsBlocked(status)})
	}

	return results, nil
}

func send(rawURL string, headers map[string]string, client *stealth.Client) (int, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
