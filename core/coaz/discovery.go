package coaz

// Discovery: fetch the MCP server's tools/list (streamable HTTP transport)
// and index each tool's COAZ declaration. Results are cached per upstream URL
// with a TTL; compiled mappings are cached alongside.
//
// The client first tries a bare tools/list (works with stateless MCP
// servers); if the server demands a session it performs the
// initialize -> notifications/initialized -> tools/list handshake, carrying
// the Mcp-Session-Id header.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const mcpProtocolVersion = "2025-03-26"

type discoveredTool struct {
	tool       Tool
	mapping    *CompiledMapping
	mappingErr error // a broken declared mapping is a per-call -32602
}

type discoveryEntry struct {
	tools     map[string]*discoveredTool
	fetchedAt time.Time
	err       error
}

type discoveryCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*discoveryEntry
	httpc   *http.Client
}

func newDiscoveryCache(ttl time.Duration, httpc *http.Client) *discoveryCache {
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	return &discoveryCache{ttl: ttl, entries: map[string]*discoveryEntry{}, httpc: httpc}
}

// lookup returns the COAZ view of one tool on the given MCP upstream.
func (d *discoveryCache) lookup(ctx context.Context, upstreamURL, authorization, toolName string) (*discoveredTool, error) {
	d.mu.Lock()
	entry, ok := d.entries[upstreamURL]
	fresh := ok && time.Since(entry.fetchedAt) < d.ttl
	d.mu.Unlock()

	if !fresh {
		tools, err := d.fetchTools(ctx, upstreamURL, authorization)
		entry = &discoveryEntry{tools: tools, fetchedAt: time.Now(), err: err}
		d.mu.Lock()
		// keep serving a previous good entry if the refresh failed
		if err != nil {
			if prev, ok := d.entries[upstreamURL]; ok && prev.err == nil {
				entry = prev
			}
		}
		d.entries[upstreamURL] = entry
		d.mu.Unlock()
	}
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.tools[toolName], nil
}

func (d *discoveryCache) fetchTools(ctx context.Context, upstreamURL, authorization string) (map[string]*discoveredTool, error) {
	result, err := d.rpc(ctx, upstreamURL, authorization, "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	})
	if err != nil {
		// Server may require a session: run the initialize handshake.
		result, err = d.fetchWithSession(ctx, upstreamURL, authorization)
		if err != nil {
			return nil, fmt.Errorf("tools/list discovery from %s failed: %w", upstreamURL, err)
		}
	}

	var listed struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(result, &listed); err != nil {
		return nil, fmt.Errorf("tools/list result malformed: %w", err)
	}
	tools := make(map[string]*discoveredTool, len(listed.Tools))
	for _, raw := range listed.Tools {
		var t Tool
		if err := json.Unmarshal(raw, &t); err != nil || t.Name == "" {
			continue
		}
		dt := &discoveredTool{tool: t}
		if t.Coaz {
			rawMapping, ok := t.InputSchema["x-coaz-mapping"].(map[string]any)
			if !ok {
				dt.mappingErr = fmt.Errorf("tool %q declares coaz but inputSchema has no x-coaz-mapping object", t.Name)
			} else {
				dt.mapping, dt.mappingErr = CompileMapping(t.Name, rawMapping)
			}
		}
		tools[t.Name] = dt
	}
	return tools, nil
}

func (d *discoveryCache) fetchWithSession(ctx context.Context, upstreamURL, authorization string) (json.RawMessage, error) {
	var session string
	_, session, err := d.rpcWithSession(ctx, upstreamURL, authorization, "", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "coaz-pep", "version": "1.0"},
		},
	})
	if err != nil {
		return nil, err
	}
	// best-effort; some servers require it before serving requests
	_, _, _ = d.rpcWithSession(ctx, upstreamURL, authorization, session, map[string]any{
		"jsonrpc": "2.0", "method": "notifications/initialized",
	})
	result, _, err := d.rpcWithSession(ctx, upstreamURL, authorization, session, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	})
	return result, err
}

func (d *discoveryCache) rpc(ctx context.Context, url, authorization, session string, payload map[string]any) (json.RawMessage, error) {
	result, _, err := d.rpcWithSession(ctx, url, authorization, session, payload)
	return result, err
}

// rpcWithSession POSTs one JSON-RPC message and returns the result member of
// the matching response, handling both application/json and SSE-framed
// (text/event-stream) replies.
func (d *discoveryCache) rpcWithSession(ctx context.Context, url, authorization, session string, payload map[string]any) (json.RawMessage, string, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", mcpProtocolVersion)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := d.httpc.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	newSession := resp.Header.Get("Mcp-Session-Id")
	if newSession == "" {
		newSession = session
	}
	if resp.StatusCode == http.StatusAccepted { // notifications
		return nil, newSession, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, newSession, fmt.Errorf("MCP upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	ct := resp.Header.Get("Content-Type")
	var msg []byte
	if strings.HasPrefix(ct, "text/event-stream") {
		msg, err = firstSSEData(resp.Body)
		if err != nil {
			return nil, newSession, err
		}
	} else {
		msg, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if err != nil {
			return nil, newSession, err
		}
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg, &rpcResp); err != nil {
		return nil, newSession, fmt.Errorf("MCP response is not JSON-RPC: %w", err)
	}
	if rpcResp.Error != nil {
		return nil, newSession, fmt.Errorf("MCP error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}
	return rpcResp.Result, newSession, nil
}

// firstSSEData returns the first `data:` payload of an SSE stream.
func firstSSEData(r io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	var data bytes.Buffer
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		} else if line == "" && data.Len() > 0 {
			return data.Bytes(), nil
		}
	}
	if data.Len() > 0 {
		return data.Bytes(), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no data frame in SSE response")
}
