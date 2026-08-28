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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const mcpProtocolVersion = "2025-03-26"

type discoveredTool struct {
	tool    Tool
	dialect Dialect
	// exactly one of these is set, per dialect
	mapping    *CompiledMapping   // v1
	mappingV2  *CompiledMappingV2 // v2
	mappingErr error              // a broken declared mapping is a per-call -32602
}

// declared reports whether this tool carries a COAZ mapping in either dialect.
func (dt *discoveredTool) declared() bool {
	return dt != nil && (dt.mapping != nil || dt.mappingV2 != nil || dt.mappingErr != nil)
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
	// maxEntries bounds the map. Keys include a hash of the caller's credential, so
	// without a cap a stream of distinct tokens grows it without limit.
	maxEntries int
}

// maxDiscoveryEntries is generous for real deployments — a handful of upstreams times
// the credentials in play — and far below anything that would strain memory.
const maxDiscoveryEntries = 4096

// evictLocked drops expired entries, and if that is not enough, refuses to grow.
// Reporting failure rather than evicting a live entry keeps the cache predictable under
// a flood: a caller gets a discovery error (fail closed) instead of silent thrashing.
func (d *discoveryCache) evictLocked(now time.Time) bool {
	if len(d.entries) < d.maxEntries {
		return true
	}
	for k, e := range d.entries {
		if now.Sub(e.fetchedAt) >= d.ttl {
			delete(d.entries, k)
		}
	}
	return len(d.entries) < d.maxEntries
}

func newDiscoveryCache(ttl time.Duration, httpc *http.Client) *discoveryCache {
	if httpc == nil {
		httpc = &http.Client{Timeout: 15 * time.Second}
	}
	return &discoveryCache{ttl: ttl, entries: map[string]*discoveryEntry{}, httpc: httpc, maxEntries: maxDiscoveryEntries}
}

// cacheKey binds a cached tools/list to BOTH the upstream and the credential it was
// fetched with. Keying on the URL alone leaks one caller's view of the tools — and so
// their mappings — to every other caller for the whole TTL, whenever an MCP server
// tailors tools/list per caller. The credential is hashed, never stored.
func cacheKey(upstreamURL, authorization string) string {
	sum := sha256.Sum256([]byte(authorization))
	return upstreamURL + "\x00" + base64.RawURLEncoding.EncodeToString(sum[:8])
}

// lookup returns the COAZ view of one tool on the given MCP upstream.
func (d *discoveryCache) lookup(ctx context.Context, upstreamURL, authorization, toolName string) (*discoveredTool, error) {
	key := cacheKey(upstreamURL, authorization)
	d.mu.Lock()
	entry, ok := d.entries[key]
	fresh := ok && time.Since(entry.fetchedAt) < d.ttl
	d.mu.Unlock()

	if !fresh {
		tools, err := d.fetchTools(ctx, upstreamURL, authorization)
		entry = &discoveryEntry{tools: tools, fetchedAt: time.Now(), err: err}
		d.mu.Lock()
		// keep serving a previous good entry if the refresh failed
		if err != nil {
			if prev, ok := d.entries[key]; ok && prev.err == nil {
				entry = prev
			}
		}
		if _, replacing := d.entries[key]; replacing || d.evictLocked(time.Now()) {
			d.entries[key] = entry
		} else {
			// At capacity with nothing to expire: serve this result without caching it
			// rather than letting the map grow unbounded.
			d.mu.Unlock()
			if entry.err != nil {
				return nil, entry.err
			}
			return entry.tools[toolName], nil
		}
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
		// v2 first: a tool carrying x-authzen-mapping is declared against the current
		// drafts, whatever else it says. The v1 `coaz: true` marker no longer exists,
		// so its presence is the only thing that selects the superseded dialect.
		if rawV2, ok := t.InputSchema["x-authzen-mapping"].(map[string]any); ok {
			dt.dialect = DialectV2
			dt.mappingV2, dt.mappingErr = CompileMappingV2(t.Name, rawV2)
			if dt.mappingErr == nil && !dt.mappingV2.Anchored() {
				// Not fatal — the binding permits it — but a gateway is enforcing a
				// mapping the MCP server authored, and an unanchored subject means that
				// server is asserting who the caller is.
				log.Printf("coaz: tool %q sets subject.id from a source that cannot be "+
					"verified against the token; its identity is asserted by the mapping author", t.Name)
			}
		} else if t.Coaz {
			dt.dialect = DialectV1
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
