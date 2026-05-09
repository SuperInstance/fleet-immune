# fleet-immune ⚒️

**Fleet immune system** — intrusion detection, self/non-self discrimination, anomaly detection for multi-agent fleets.

Zero external dependencies. Pure Rust.

## Inspiration

The biological immune system solves an elegant problem: discriminate **self** from **non-self** without a pre-defined list of threats. It uses statistical pattern matching — lymphocytes that bind to molecular patterns with varying affinity.

E158 (*The Art of Self/Non-Self Discrimination*) describes how immune systems learn a "self" baseline during a training phase, then continuously monitor for deviations. Any agent whose behavior deviates beyond a statistical threshold is flagged as non-self and quarantined.

This crate applies the same logic to software fleets:

1. **Learn** — during a known-good period, collect behavioral state vectors (CPU, memory, message rate, latency, connection count…) and compute mean + standard deviation for each dimension.
2. **Monitor** — at runtime, compare each agent's current state against the learned profile.
3. **Detect** — flag agents whose anomaly score (sum of σ-excess across dimensions) exceeds a configurable threshold.
4. **Respond** — quarantine flagged agents by zeroing their state, removing them from fleet coordination.

## How It Works

### SelfProfile

Learns the statistical fingerprint of normal fleet behavior:

```rust
use fleet_immune::SelfProfile;

let normal_states = vec![
    vec![0.1, 0.2, 0.3],
    vec![0.2, 0.3, 0.4],
    vec![0.3, 0.4, 0.5],
];
let profile = SelfProfile::learn(&normal_states);
```

- `mean_state` — average of each dimension
- `std_state` — population standard deviation of each dimension
- `correlation_baseline` — mean pairwise Pearson correlation among training states

### IntrusionDetector

Wraps a `SelfProfile` with a sigma threshold and tracks detection history:

```rust
let mut detector = IntrusionDetector::new(profile, 3.0);
```

**Per-agent check:** each state is scored by how many σ it deviates from the mean beyond the 3σ self-region.

**Correlation check:** if the fleet loses internal correlation (agents start behaving independently), it's flagged — even if no single agent crosses its threshold.

**False positive rate:** estimated from the rolling history of anomaly scores.

### ImmuneResponse

Reports which agents to quarantine.

```rust
let resp = detector.response(&detections);
resp.quarantine(&mut agent_states); // zero out compromised agents
```

## API

| Type | Method | Description |
|------|--------|-------------|
| `SelfProfile` | `learn(states)` | Learn self profile from normal states |
| `SelfProfile` | `is_self(state)` | True if all dims are within 3σ of mean |
| `SelfProfile` | `anomaly_score(state)` | Sum of σ-excess outside 3σ region |
| `IntrusionDetector` | `new(profile, threshold)` | Create detector with self profile |
| `IntrusionDetector` | `check(states)` | Score each agent state → `Vec<Detection>` |
| `IntrusionDetector` | `check_correlation(states)` | Detect fleet correlation loss |
| `IntrusionDetector` | `response(detections)` | Build immune response from detections |
| `IntrusionDetector` | `false_positive_rate()` | Fraction of history exceeding threshold |
| `ImmuneResponse` | `quarantine(agent_states)` | Zero out quarantined agents |
| `ImmuneResponse` | `is_clean()` | True if no agents quarantined |

## Tests

```
cargo test
```

22 tests covering: self profile learning, self/non-self discrimination, anomaly scoring, correlation-based detection, immune response, quarantine, false positive rate tracking, multi-agent detection.

## License

MIT
