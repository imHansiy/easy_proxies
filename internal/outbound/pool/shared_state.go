package pool

import (
	"sync"
	"sync/atomic"
	"time"

	"easy_proxies/internal/monitor"
)

// SharedRuntimeState mirrors shared pool state for persistence.
type SharedRuntimeState struct {
	Tag              string
	Failures         int
	Blacklisted      bool
	BlacklistedUntil time.Time
}

// SharedStateStore persists shared pool state.
type SharedStateStore interface {
	LoadSharedRuntimeState(tag string) (SharedRuntimeState, bool, error)
	SaveSharedRuntimeState(state SharedRuntimeState) error
	DeleteSharedRuntimeState(tag string) error
}

var (
	sharedRuntimeStoreMu sync.RWMutex
	sharedRuntimeStore   SharedStateStore
)

// SetSharedStateStore configures persistence for shared pool state.
func SetSharedStateStore(store SharedStateStore) {
	sharedRuntimeStoreMu.Lock()
	sharedRuntimeStore = store
	sharedRuntimeStoreMu.Unlock()
}

func currentSharedRuntimeStore() SharedStateStore {
	sharedRuntimeStoreMu.RLock()
	defer sharedRuntimeStoreMu.RUnlock()
	return sharedRuntimeStore
}

// sharedMemberState holds failure/blacklist state shared across all pool instances.
// This enables hybrid mode where pool and multi-port modes share the same node state.
type sharedMemberState struct {
	mu               sync.Mutex
	tag              string
	failures         int
	blacklisted      bool
	blacklistedUntil time.Time
	domainFailures   map[string]int
	domainBlacklist  map[string]time.Time
	entry            atomic.Pointer[monitor.EntryHandle]
	active           atomic.Int32
}

var sharedStateStore sync.Map // map[tag]*sharedMemberState

// acquireSharedState returns the shared state for a tag, creating if needed.
func acquireSharedState(tag string) *sharedMemberState {
	if v, ok := sharedStateStore.Load(tag); ok {
		return v.(*sharedMemberState)
	}
	state := &sharedMemberState{tag: tag, domainFailures: make(map[string]int), domainBlacklist: make(map[string]time.Time)}
	if store := currentSharedRuntimeStore(); store != nil {
		if persisted, ok, err := store.LoadSharedRuntimeState(tag); err == nil && ok {
			state.failures = persisted.Failures
			state.blacklisted = persisted.Blacklisted
			state.blacklistedUntil = persisted.BlacklistedUntil
		}
	}
	actual, _ := sharedStateStore.LoadOrStore(tag, state)
	return actual.(*sharedMemberState)
}

// lookupSharedState returns the shared state if it exists.
func lookupSharedState(tag string) (*sharedMemberState, bool) {
	v, ok := sharedStateStore.Load(tag)
	if !ok {
		return nil, false
	}
	return v.(*sharedMemberState), true
}

// ResetSharedStateStore clears all shared state (used during config reload).
func ResetSharedStateStore() {
	sharedStateStore.Range(func(key, _ any) bool {
		sharedStateStore.Delete(key)
		return true
	})
}

func (s *sharedMemberState) attachEntry(entry *monitor.EntryHandle) {
	if entry == nil {
		return
	}
	s.entry.Store(entry)
}

func (s *sharedMemberState) entryHandle() *monitor.EntryHandle {
	return s.entry.Load()
}

// recordFailure increments failure count and triggers blacklist if threshold reached.
// Returns: (current failures, blacklisted, blacklist until time)
func (s *sharedMemberState) recordFailure(cause error, threshold int, duration time.Duration) (int, bool, time.Time) {
	s.mu.Lock()
	s.failures++
	count := s.failures
	triggered := false
	var until time.Time
	if s.failures >= threshold {
		triggered = true
		until = time.Now().Add(duration)
		s.failures = 0
		s.blacklisted = true
		s.blacklistedUntil = until
	}
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.RecordFailure(cause)
		if triggered {
			entry.Blacklist(until)
		}
	}
	s.persist()
	return count, triggered, until
}

func (s *sharedMemberState) recordSuccess() {
	s.mu.Lock()
	s.failures = 0
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.RecordSuccess()
	}
	s.persist()
}

// isBlacklisted checks if the node is currently blacklisted, auto-clearing if expired.
func (s *sharedMemberState) isBlacklisted(now time.Time) bool {
	s.mu.Lock()
	expired := s.blacklisted && now.After(s.blacklistedUntil)
	if expired {
		s.blacklisted = false
		s.blacklistedUntil = time.Time{}
	}
	blacklisted := s.blacklisted
	s.mu.Unlock()

	if expired {
		if entry := s.entry.Load(); entry != nil {
			entry.ClearBlacklist()
		}
		s.persist()
	}
	return blacklisted
}

func (s *sharedMemberState) forceRelease() {
	s.mu.Lock()
	s.failures = 0
	s.blacklisted = false
	s.blacklistedUntil = time.Time{}
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.ClearBlacklist()
	}
	s.persist()
}

func (s *sharedMemberState) recordDomainFailure(domain string, threshold int, duration time.Duration) (int, bool, time.Time) {
	if domain == "" {
		return 0, false, time.Time{}
	}
	now := time.Now()
	s.mu.Lock()
	if s.domainFailures == nil {
		s.domainFailures = make(map[string]int)
	}
	if s.domainBlacklist == nil {
		s.domainBlacklist = make(map[string]time.Time)
	}
	if until, ok := s.domainBlacklist[domain]; ok && !until.IsZero() && now.After(until) {
		delete(s.domainBlacklist, domain)
	}
	s.domainFailures[domain]++
	count := s.domainFailures[domain]
	triggered := false
	var until time.Time
	if count >= threshold {
		triggered = true
		// Permanent domain blacklist (no automatic release).
		// Keep zero time to indicate "never expires".
		_ = duration
		until = time.Time{}
		s.domainBlacklist[domain] = until
		s.domainFailures[domain] = 0
	}
	snapshot := s.domainSnapshotLocked(now)
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.SetDomainBlacklist(snapshot)
	}
	s.persist()
	return count, triggered, until
}

func (s *sharedMemberState) isDomainBlacklisted(domain string, now time.Time) bool {
	if domain == "" {
		return false
	}
	s.mu.Lock()
	if s.domainBlacklist == nil {
		s.mu.Unlock()
		return false
	}
	until, ok := s.domainBlacklist[domain]
	if !ok {
		s.mu.Unlock()
		return false
	}
	if !until.IsZero() && now.After(until) {
		delete(s.domainBlacklist, domain)
		snapshot := s.domainSnapshotLocked(now)
		s.mu.Unlock()
		if entry := s.entry.Load(); entry != nil {
			entry.SetDomainBlacklist(snapshot)
		}
		s.persist()
		return false
	}
	s.mu.Unlock()
	return true
}

func (s *sharedMemberState) domainsForRecheck(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.domainBlacklist) == 0 {
		return nil
	}
	domains := make([]string, 0, len(s.domainBlacklist))
	for domain, until := range s.domainBlacklist {
		if !until.IsZero() && now.After(until) {
			delete(s.domainBlacklist, domain)
			continue
		}
		domains = append(domains, domain)
	}
	return domains
}

func (s *sharedMemberState) clearDomainBlacklist(domain string) bool {
	if domain == "" {
		return false
	}
	s.mu.Lock()
	if s.domainBlacklist == nil {
		s.mu.Unlock()
		return false
	}
	if _, ok := s.domainBlacklist[domain]; !ok {
		s.mu.Unlock()
		return false
	}
	delete(s.domainBlacklist, domain)
	delete(s.domainFailures, domain)
	snapshot := s.domainSnapshotLocked(time.Now())
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.SetDomainBlacklist(snapshot)
	}
	s.persist()
	return true
}

func (s *sharedMemberState) domainSnapshotLocked(now time.Time) []monitor.DomainBlock {
	if len(s.domainBlacklist) == 0 {
		return nil
	}
	out := make([]monitor.DomainBlock, 0, len(s.domainBlacklist))
	for domain, until := range s.domainBlacklist {
		if !until.IsZero() && now.After(until) {
			delete(s.domainBlacklist, domain)
			continue
		}
		out = append(out, monitor.DomainBlock{Domain: domain, BlacklistedUntil: until})
	}
	return out
}

func (s *sharedMemberState) incActive() {
	s.active.Add(1)
	if entry := s.entry.Load(); entry != nil {
		entry.IncActive()
	}
}

func (s *sharedMemberState) decActive() {
	s.active.Add(-1)
	if entry := s.entry.Load(); entry != nil {
		entry.DecActive()
	}
}

func (s *sharedMemberState) activeCount() int32 {
	return s.active.Load()
}

// releaseSharedMember clears blacklist state for a tag (called from release functions).
func releaseSharedMember(tag string) {
	if state, ok := lookupSharedState(tag); ok {
		state.forceRelease()
	}
}

func (s *sharedMemberState) persist() {
	store := currentSharedRuntimeStore()
	if store == nil || s == nil {
		return
	}
	s.mu.Lock()
	state := SharedRuntimeState{
		Tag:              s.tag,
		Failures:         s.failures,
		Blacklisted:      s.blacklisted,
		BlacklistedUntil: s.blacklistedUntil,
	}
	s.mu.Unlock()
	_ = store.SaveSharedRuntimeState(state)
}
