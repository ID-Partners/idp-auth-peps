package federation

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/ID-Partners/idp-auth-peps/core/internal/metafetch"
)

// walk fetches and validates a Trust Chain from entityID up to one of the configured
// Trust Anchors (§10.1–10.3). The returned chain is ES[0]..ES[i]: the subject's Entity
// Configuration, the Subordinate Statements upward, and the anchor's Entity
// Configuration, every link verified.
func (r *Resolver) walk(ctx context.Context, entityID string) ([]*Statement, string, error) {
	w := &walker{r: r, ctx: ctx, configs: map[string]*Statement{}, budget: r.opts.MaxFetches}

	leaf, err := w.entityConfiguration(entityID)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			return nil, "", err
		}
		if errors.Is(err, metafetch.ErrNotFound) {
			return nil, "", ErrNotFederated
		}
		return nil, "", err
	}
	if _, isAnchor := r.anchors[entityID]; isAnchor {
		return nil, "", fmt.Errorf("%w: %s is a trust anchor, not a subject", ErrInvalidChain, entityID)
	}
	if len(leaf.AuthorityHints) == 0 {
		return nil, "", fmt.Errorf("%w: %s has no authority_hints", ErrInvalidChain, entityID)
	}

	type frontierItem struct {
		chain []*Statement // ES[0..j], the last element is the current subject's statement
	}
	frontier := []frontierItem{{chain: []*Statement{leaf}}}
	visited := map[string]bool{entityID: true}
	var best []*Statement
	bestAnchor := ""
	var lastErr error

	for len(frontier) > 0 {
		item := frontier[0]
		frontier = frontier[1:]
		// The last statement was issued by the entity we now climb from: for ES[0]
		// that is the leaf itself, for a Subordinate Statement it is the Superior that
		// signed it. Its Entity Configuration carries the next authority_hints.
		child := item.chain[len(item.chain)-1]
		current := child.Iss
		currentConfig := w.configs[current]
		// Intermediates so far: every statement past ES[0] was issued by one. Adding a
		// link makes `current` an intermediate unless the superior is an anchor.
		intermediates := len(item.chain) - 1

		for _, hint := range currentConfig.AuthorityHints {
			if visited[hint] {
				continue
			}
			_, isAnchor := r.anchors[hint]
			if !isAnchor && intermediates+1 > r.opts.MaxPathLength {
				lastErr = fmt.Errorf("%w: path through %s exceeds max path length %d", ErrInvalidChain, hint, r.opts.MaxPathLength)
				continue
			}
			superior, err := w.entityConfiguration(hint)
			if err != nil {
				if errors.Is(err, ErrNotAllowed) {
					return nil, "", err
				}
				lastErr = err
				continue
			}
			sub, err := w.subordinateStatement(superior, current)
			if err != nil {
				if errors.Is(err, ErrNotAllowed) {
					return nil, "", err
				}
				lastErr = err
				continue
			}
			// §4: ES[j] is signed by a key in ES[j+1].jwks — the statement `current`
			// issued must verify against the keys its Superior asserts for it, not
			// only against its own Entity Configuration.
			if err := child.verifyWith(sub.JWKS); err != nil {
				lastErr = fmt.Errorf("%w: statement issued by %s does not verify against %s's subordinate statement: %v", ErrInvalidChain, current, hint, err)
				continue
			}
			chain := append(append([]*Statement{}, item.chain...), sub)
			if isAnchor {
				chain = append(chain, superior)
				if best == nil || r.order[hint] < r.order[bestAnchor] {
					best, bestAnchor = chain, hint
				}
				if r.order[hint] == 0 {
					return best, bestAnchor, nil // the preferred anchor: nothing beats it
				}
				continue
			}
			visited[hint] = true
			frontier = append(frontier, frontierItem{chain: chain})
		}
	}
	if best != nil {
		return best, bestAnchor, nil
	}
	if lastErr != nil {
		if errors.Is(lastErr, ErrInvalidChain) {
			return nil, "", lastErr
		}
		return nil, "", fmt.Errorf("no trust chain to a configured anchor: %w", lastErr)
	}
	return nil, "", fmt.Errorf("%w: no path from %s reaches a configured trust anchor", ErrInvalidChain, entityID)
}

type walker struct {
	r       *Resolver
	ctx     context.Context
	configs map[string]*Statement // verified Entity Configurations seen this resolution
	budget  int
}

func (w *walker) get(raw string) ([]byte, error) {
	if w.budget <= 0 {
		return nil, fmt.Errorf("fetch budget of %d exhausted", w.r.opts.MaxFetches)
	}
	w.budget--
	return w.r.fetch.Get(w.ctx, raw, contentType)
}

// entityConfiguration fetches and verifies the self-issued statement of entityID. A
// configured Trust Anchor's is verified against the out-of-band keys; anyone else's
// against its own jwks (§4: ES[0] and ES[i] are self-signed).
func (w *walker) entityConfiguration(entityID string) (*Statement, error) {
	if st, ok := w.configs[entityID]; ok {
		return st, nil
	}
	body, err := w.get(strings.TrimRight(entityID, "/") + WellKnown)
	if err != nil {
		if errors.Is(err, ErrNotAllowed) || errors.Is(err, metafetch.ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("fetching entity configuration of %s: %w", entityID, err)
	}
	st, err := parseStatement(strings.TrimSpace(string(body)), w.r.opts.Now(), w.r.opts.Leeway)
	if err != nil {
		return nil, fmt.Errorf("%w: entity configuration of %s: %v", ErrInvalidChain, entityID, err)
	}
	if !st.IsEntityConfiguration() || st.Sub != entityID {
		return nil, fmt.Errorf("%w: %s's entity configuration is about %s (iss %s)", ErrInvalidChain, entityID, st.Sub, st.Iss)
	}
	keys := st.JWKS
	if ta, isAnchor := w.r.anchors[entityID]; isAnchor {
		keys = ta.Keys
	}
	if err := st.verifyWith(keys); err != nil {
		return nil, fmt.Errorf("%w: entity configuration of %s: %v", ErrInvalidChain, entityID, err)
	}
	w.configs[entityID] = st
	return st, nil
}

// subordinateStatement asks superior's fetch endpoint about sub and verifies the
// answer with the superior's Federation Entity Keys.
func (w *walker) subordinateStatement(superior *Statement, sub string) (*Statement, error) {
	endpoint := ""
	if fe, ok := superior.Metadata[entityTypeFedEnt]; ok {
		endpoint, _ = fe["federation_fetch_endpoint"].(string)
	}
	if endpoint == "" {
		return nil, fmt.Errorf("%w: %s publishes no federation_fetch_endpoint", ErrInvalidChain, superior.Sub)
	}
	u, err := url.Parse(endpoint)
	if err != nil || !u.IsAbs() || u.Fragment != "" {
		return nil, fmt.Errorf("%w: %s's federation_fetch_endpoint is not a URL", ErrInvalidChain, superior.Sub)
	}
	q := u.Query()
	q.Set("sub", sub)
	q.Set("iss", superior.Sub)
	u.RawQuery = q.Encode()

	body, err := w.get(u.String())
	if err != nil {
		if errors.Is(err, ErrNotAllowed) {
			return nil, err
		}
		return nil, fmt.Errorf("fetching subordinate statement about %s from %s: %w", sub, superior.Sub, err)
	}
	st, err := parseStatement(strings.TrimSpace(string(body)), w.r.opts.Now(), w.r.opts.Leeway)
	if err != nil {
		return nil, fmt.Errorf("%w: subordinate statement about %s from %s: %v", ErrInvalidChain, sub, superior.Sub, err)
	}
	if st.IsEntityConfiguration() || st.Iss != superior.Sub || st.Sub != sub {
		return nil, fmt.Errorf("%w: %s returned a statement about %s issued by %s", ErrInvalidChain, superior.Sub, st.Sub, st.Iss)
	}
	if err := st.verifyWith(superior.JWKS); err != nil {
		return nil, fmt.Errorf("%w: subordinate statement about %s: %v", ErrInvalidChain, sub, err)
	}
	return st, nil
}
