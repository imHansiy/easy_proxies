package pool

import (
	"strings"
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
	mu                     sync.Mutex
	tag                    string
	poolName               string
	stateKey               string
	failures               int
	autoBlacklistedUntil   time.Time
	manualBlacklistedUntil time.Time
	domainFailures         map[string]int
	domainBlacklist        map[string]time.Time
	entry                  atomic.Pointer[monitor.EntryHandle]
	active                 atomic.Int32
}

var sharedStateStore sync.Map // map[tag]*sharedMemberState

func normalizePoolName(poolName string) string {
	poolName = strings.TrimSpace(poolName)
	if poolName == "" {
		return "default"
	}
	return poolName
}

func sharedStateKey(poolName, tag string) string {
	poolName = normalizePoolName(poolName)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return poolName + "::unknown"
	}
	return poolName + "::" + tag
}

// acquireSharedState returns the shared state for a (pool,tag), creating if needed.
func acquireSharedState(poolName, tag string) *sharedMemberState {
	key := sharedStateKey(poolName, tag)
	if v, ok := sharedStateStore.Load(key); ok {
		return v.(*sharedMemberState)
	}
	state := &sharedMemberState{
		tag:             tag,
		poolName:        normalizePoolName(poolName),
		stateKey:        key,
		domainFailures:  make(map[string]int),
		domainBlacklist: make(map[string]time.Time),
	}
	if store := currentSharedRuntimeStore(); store != nil {
		if persisted, ok, err := store.LoadSharedRuntimeState(key); err == nil && ok {
			state.failures = persisted.Failures
			if persisted.Blacklisted && !persisted.BlacklistedUntil.IsZero() {
				state.manualBlacklistedUntil = persisted.BlacklistedUntil
			}
		}
	}
	actual, _ := sharedStateStore.LoadOrStore(key, state)
	return actual.(*sharedMemberState)
}

// lookupSharedState returns the shared state if it exists.
func lookupSharedState(poolName, tag string) (*sharedMemberState, bool) {
	v, ok := sharedStateStore.Load(sharedStateKey(poolName, tag))
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
	now := time.Now()
	s.mu.Lock()
	until := s.effectiveBlacklistUntilLocked(now)
	domainSnapshot := s.domainSnapshotLocked(now)
	s.mu.Unlock()
	if !until.IsZero() && now.Before(until) {
		entry.Blacklist(until)
	}
	entry.SetDomainBlacklist(domainSnapshot)
}

func (s *sharedMemberState) entryHandle() *monitor.EntryHandle {
	return s.entry.Load()
}

func (s *sharedMemberState) expireLocked(now time.Time) bool {
	changed := false
	if !s.autoBlacklistedUntil.IsZero() && now.After(s.autoBlacklistedUntil) {
		s.autoBlacklistedUntil = time.Time{}
		changed = true
	}
	if !s.manualBlacklistedUntil.IsZero() && now.After(s.manualBlacklistedUntil) {
		s.manualBlacklistedUntil = time.Time{}
		changed = true
	}
	return changed
}

func (s *sharedMemberState) effectiveBlacklistUntilLocked(now time.Time) time.Time {
	_ = s.expireLocked(now)
	if s.autoBlacklistedUntil.After(s.manualBlacklistedUntil) {
		return s.autoBlacklistedUntil
	}
	return s.manualBlacklistedUntil
}

// recordFailure increments failure count and triggers blacklist if threshold reached.
// Returns: (current failures, blacklisted, blacklist until time)
func (s *sharedMemberState) recordFailure(cause error, threshold int, duration time.Duration) (int, bool, time.Time) {
	if threshold <= 0 {
		threshold = 1
	}
	if duration <= 0 {
		duration = time.Minute
	}
	now := time.Now()

	s.mu.Lock()
	s.expireLocked(now)
	s.failures++
	count := s.failures
	triggered := false
	var until time.Time
	if s.failures >= threshold {
		triggered = true
		s.autoBlacklistedUntil = now.Add(duration)
		until = s.effectiveBlacklistUntilLocked(now)
		s.failures = 0
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
	now := time.Now()
	changed := s.expireLocked(now)
	s.failures = 0
	stillBlacklisted := !s.effectiveBlacklistUntilLocked(now).IsZero()
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.RecordSuccess()
		if changed {
			if stillBlacklisted {
				entry.Blacklist(s.effectiveBlacklistUntil())
			} else {
				entry.ClearBlacklist()
			}
		}
	}
	s.persist()
}

// isBlacklisted checks if the node is currently blacklisted, auto-clearing if expired.
func (s *sharedMemberState) isBlacklisted(now time.Time) bool {
	s.mu.Lock()
	expired := s.expireLocked(now)
	blacklisted := !s.effectiveBlacklistUntilLocked(now).IsZero()
	until := s.effectiveBlacklistUntilLocked(now)
	s.mu.Unlock()

	if expired {
		if entry := s.entry.Load(); entry != nil {
			if blacklisted {
				entry.Blacklist(until)
			} else {
				entry.ClearBlacklist()
			}
		}
		s.persist()
	}
	return blacklisted
}

func (s *sharedMemberState) effectiveBlacklistUntil() time.Time {
	now := time.Now()
	s.mu.Lock()
	until := s.effectiveBlacklistUntilLocked(now)
	s.mu.Unlock()
	return until
}

func (s *sharedMemberState) hasAutoBlacklist(now time.Time) bool {
	s.mu.Lock()
	changed := s.expireLocked(now)
	auto := !s.autoBlacklistedUntil.IsZero()
	blacklisted := !s.effectiveBlacklistUntilLocked(now).IsZero()
	until := s.effectiveBlacklistUntilLocked(now)
	s.mu.Unlock()

	if changed {
		if entry := s.entry.Load(); entry != nil {
			if blacklisted {
				entry.Blacklist(until)
			} else {
				entry.ClearBlacklist()
			}
		}
		s.persist()
	}
	return auto
}

func (s *sharedMemberState) clearAutoBlacklist() {
	now := time.Now()
	s.mu.Lock()
	changed := !s.autoBlacklistedUntil.IsZero() || s.failures > 0
	s.autoBlacklistedUntil = time.Time{}
	s.failures = 0
	stillBlacklisted := !s.effectiveBlacklistUntilLocked(now).IsZero()
	until := s.effectiveBlacklistUntilLocked(now)
	s.mu.Unlock()

	if !changed {
		return
	}
	if entry := s.entry.Load(); entry != nil {
		if stillBlacklisted {
			entry.Blacklist(until)
		} else {
			entry.ClearBlacklist()
		}
	}
	s.persist()
}

func (s *sharedMemberState) manualBan(duration time.Duration) time.Time {
	if duration <= 0 {
		duration = time.Minute
	}
	now := time.Now()
	until := now.Add(duration)

	s.mu.Lock()
	if until.After(s.manualBlacklistedUntil) {
		s.manualBlacklistedUntil = until
	}
	s.failures = 0
	effective := s.effectiveBlacklistUntilLocked(now)
	s.mu.Unlock()

	if entry := s.entry.Load(); entry != nil {
		entry.Blacklist(effective)
	}
	s.persist()
	return effective
}

func (s *sharedMemberState) forceRelease() {
	s.mu.Lock()
	s.failures = 0
	s.autoBlacklistedUntil = time.Time{}
	s.manualBlacklistedUntil = time.Time{}
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
	if threshold <= 0 {
		threshold = 1
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
		// Keep domain blacklist persistent and rely on background recheck for recovery.
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

// releaseSharedMember clears blacklist state for a (pool,tag) key.
func releaseSharedMember(poolName, tag string) {
	if state, ok := lookupSharedState(poolName, tag); ok {
		state.forceRelease()
	}
}

func banSharedMember(poolName, tag string, duration time.Duration) (time.Time, bool) {
	state := acquireSharedState(poolName, tag)
	if state == nil {
		return time.Time{}, false
	}
	return state.manualBan(duration), true
}

func (s *sharedMemberState) persist() {
	store := currentSharedRuntimeStore()
	if store == nil || s == nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	until := s.effectiveBlacklistUntilLocked(now)
	state := SharedRuntimeState{
		Tag:              s.stateKey,
		Failures:         s.failures,
		Blacklisted:      !until.IsZero() && now.Before(until),
		BlacklistedUntil: until,
	}
	s.mu.Unlock()
	_ = store.SaveSharedRuntimeState(state)
}
