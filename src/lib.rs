/// Fleet immune system: intrusion detection, self/non-self discrimination,
/// anomaly detection for multi-agent fleets.
///
/// Inspired by the biological immune system (E158 — The Art of Self/Non-Self
/// Discrimination). At runtime, agent behavioral states are compared against
/// a learned "self" profile. States that deviate statistically are flagged as
/// anomalous and the fleet can quarantine compromised agents.

use std::f64;

// ---------------------------------------------------------------------------
// SelfProfile
// ---------------------------------------------------------------------------

/// A statistical profile of "normal" (self) fleet behavior.
///
/// Learns mean and standard deviation along each dimension of a
/// multi-dimensional state vector (e.g. CPU, memory, message rate,
/// connection count, latency percentile).
#[derive(Clone, Debug)]
pub struct SelfProfile {
    pub mean_state: Vec<f64>,
    pub std_state: Vec<f64>,
    pub correlation_baseline: f64,
}

impl SelfProfile {
    /// Learn a self profile from a slice of normal (healthy) states.
    ///
    /// Each state must be a `Vec<f64>` of the same dimensionality (the
    /// number of behavioral metrics tracked per agent). Returns `None`
    /// if `states` is empty or contains inconsistent dimensions.
    ///
    /// When `std` is zero for a dimension (constant feature), that
    /// dimension is assigned a minimum std of `1e-10` to avoid division
    /// by zero in anomaly scoring.
    pub fn learn(states: &[Vec<f64>]) -> Self {
        assert!(!states.is_empty(), "cannot learn from empty state set");
        let dim = states[0].len();
        let n = states.len() as f64;

        // Mean
        let mut sum: Vec<f64> = vec![0.0; dim];
        for s in states {
            assert_eq!(s.len(), dim, "inconsistent state dimensionality");
            for (i, &v) in s.iter().enumerate() {
                sum[i] += v;
            }
        }
        let mean_state: Vec<f64> = sum.iter().map(|&s| s / n).collect();

        // Standard deviation (population)
        let mut sq_sum: Vec<f64> = vec![0.0; dim];
        for s in states {
            for (i, &v) in s.iter().enumerate() {
                let d = v - mean_state[i];
                sq_sum[i] += d * d;
            }
        }
        let std_state: Vec<f64> = sq_sum
            .iter()
            .map(|&sq| {
                let s = (sq / n).sqrt();
                if s == 0.0 { 1e-10 } else { s }
            })
            .collect();

        // Baseline pairwise correlation among state vectors (Pearson)
        let baseline = if n > 1.0 {
            Self::pairwise_correlation_mean(states, &mean_state, &std_state)
        } else {
            1.0
        };

        Self {
            mean_state,
            std_state,
            correlation_baseline: baseline,
        }
    }

    /// Return true if `state` is within `sigma` standard deviations of the
    /// mean on *all* dimensions (the classic self/non-self test).
    pub fn is_self_within(&self, state: &[f64], sigma: f64) -> bool {
        assert_eq!(state.len(), self.mean_state.len(), "dimension mismatch");
        for i in 0..state.len() {
            let z = (state[i] - self.mean_state[i]) / self.std_state[i];
            if z.abs() > sigma {
                return false;
            }
        }
        true
    }

    /// Convenience: is_self_within(…, 3.0)
    pub fn is_self(&self, state: &[f64]) -> bool {
        self.is_self_within(state, 3.0)
    }

    /// Anomaly score: sum of how many sigmas each dimension of `state`
    /// is *outside* the 3σ self region. Dimensions inside 3σ contribute 0.
    pub fn anomaly_score(&self, state: &[f64]) -> f64 {
        assert_eq!(state.len(), self.mean_state.len(), "dimension mismatch");
        let mut score = 0.0;
        for i in 0..state.len() {
            let z = (state[i] - self.mean_state[i]) / self.std_state[i];
            let excess = z.abs() - 3.0;
            if excess > 0.0 {
                score += excess;
            }
        }
        score
    }

    // --- internal helpers ---

    /// Mean pairwise Pearson correlation across all pairs of state vectors.
    fn pairwise_correlation_mean(
        states: &[Vec<f64>],
        mean: &[f64],
        std: &[f64],
    ) -> f64 {
        let n = states.len();
        if n < 2 {
            return 1.0;
        }
        let mut total = 0.0;
        let mut count = 0;
        for i in 0..n {
            for j in (i + 1)..n {
                total += Self::pearson(&states[i], &states[j], mean, std);
                count += 1;
            }
        }
        total / count as f64
    }

    /// Pearson correlation coefficient between two state vectors.
    fn pearson(a: &[f64], b: &[f64], mean: &[f64], std: &[f64]) -> f64 {
        let dim = a.len();
        let mut cov = 0.0;
        for k in 0..dim {
            cov += (a[k] - mean[k]) * (b[k] - mean[k]) / (std[k] * std[k]);
        }
        cov / dim as f64
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// A single fleet intrusion detection result for one agent.
#[derive(Clone, Debug, PartialEq)]
pub struct Detection {
    pub detected: bool,
    pub confidence: f64,
    pub anomaly_score: f64,
    pub tick: u64,
}

// ---------------------------------------------------------------------------
// ImmuneResponse
// ---------------------------------------------------------------------------

/// Response action after detecting intrusions: identifies which agents
/// are compromised and should be quarantined.
#[derive(Clone, Debug, PartialEq)]
pub struct ImmuneResponse {
    pub quarantined_agents: Vec<usize>,
    pub anomaly_scores: Vec<f64>,
}

impl ImmuneResponse {
    /// Zero-out the states of all quarantined agents in-place.
    pub fn quarantine(&self, agent_states: &mut [Vec<f64>]) {
        for &idx in &self.quarantined_agents {
            if idx < agent_states.len() {
                for v in agent_states[idx].iter_mut() {
                    *v = 0.0;
                }
            }
        }
    }

    /// True when no agents were flagged for quarantine.
    pub fn is_clean(&self) -> bool {
        self.quarantined_agents.is_empty()
    }
}

// ---------------------------------------------------------------------------
// IntrusionDetector
// ---------------------------------------------------------------------------

/// Real-time fleet intrusion detector.
///
/// Maintains a self profile, a sigma threshold for alerting, and a rolling
/// history of anomaly scores used to estimate false positive rate.
pub struct IntrusionDetector {
    pub profile: SelfProfile,
    pub sigma_threshold: f64,
    pub history: Vec<f64>,
    tick: u64,
}

impl IntrusionDetector {
    pub fn new(profile: SelfProfile, sigma_threshold: f64) -> Self {
        Self {
            profile,
            sigma_threshold,
            history: Vec::new(),
            tick: 0,
        }
    }

    /// Check each agent's state against the self profile.
    ///
    /// Returns one `Detection` per agent state (same order).
    /// Anomaly is flagged when the anomaly score exceeds `sigma_threshold`.
    /// History records every anomaly score for FPR estimation.
    pub fn check(&mut self, states: &[Vec<f64>]) -> Vec<Detection> {
        self.tick += 1;
        let mut detections = Vec::with_capacity(states.len());
        for state in states {
            let score = self.profile.anomaly_score(state);
            self.history.push(score);
            let detected = score > self.sigma_threshold;
            // confidence = how far above threshold, clamped to [0, 1]
            let confidence = if detected {
                ((score - self.sigma_threshold) / (score + 1.0)).min(1.0)
            } else {
                0.0
            };
            detections.push(Detection {
                detected,
                confidence,
                anomaly_score: score,
                tick: self.tick,
            });
        }
        detections
    }

    /// Correlation-based detection: check if mean pairwise correlation among
    /// the current states has dropped sharply from baseline.
    ///
    /// A sudden loss of correlation can indicate that an agent is acting
    /// independently of the fleet consensus — a common symptom of intrusion.
    pub fn check_correlation(&mut self, states: &[Vec<f64>]) -> Detection {
        self.tick += 1;
        let current_corr =
            SelfProfile::pairwise_correlation_mean(states, &self.profile.mean_state, &self.profile.std_state);
        let drop = self.profile.correlation_baseline - current_corr;
        let detected = drop > self.sigma_threshold * 0.3;
        let score = drop.max(0.0);
        let confidence = if detected {
            (drop / (drop + 1.0)).min(1.0)
        } else {
            0.0
        };
        self.history.push(score);
        Detection {
            detected,
            confidence,
            anomaly_score: score,
            tick: self.tick,
        }
    }

    /// Build an `ImmuneResponse` from a batch of detections.
    ///
    /// Any agent whose anomaly score exceeds `sigma_threshold` is flagged
    /// for quarantine.
    pub fn response(&self, detections: &[Detection]) -> ImmuneResponse {
        let mut quarantined = Vec::new();
        let mut scores = Vec::new();
        for (i, d) in detections.iter().enumerate() {
            if d.anomaly_score > self.sigma_threshold {
                quarantined.push(i);
                scores.push(d.anomaly_score);
            }
        }
        ImmuneResponse {
            quarantined_agents: quarantined,
            anomaly_scores: scores,
        }
    }

    /// Estimated false positive rate based on classification history.
    ///
    /// History entries > threshold are counted as "positives". The FPR is
    /// the fraction of all history entries that exceed the threshold.
    /// Returns 0.0 when history is empty.
    pub fn false_positive_rate(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        let pos = self.history.iter().filter(|&&s| s > self.sigma_threshold).count();
        pos as f64 / self.history.len() as f64
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Self profile learning
    // -----------------------------------------------------------------------

    #[test]
    fn test_learn_self_profile() {
        let states = vec![
            vec![0.0, 0.0],
            vec![1.0, 1.0],
            vec![2.0, 2.0],
        ];
        let profile = SelfProfile::learn(&states);
        assert_eq!(profile.mean_state.len(), 2);
        assert!((profile.mean_state[0] - 1.0).abs() < 1e-10);
        assert!((profile.mean_state[1] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_learn_single_state() {
        let states = vec![vec![42.0, -3.14]];
        let profile = SelfProfile::learn(&states);
        assert!((profile.mean_state[0] - 42.0).abs() < 1e-10);
        assert!((profile.mean_state[1] - (-3.14)).abs() < 1e-10);
    }

    #[test]
    fn test_learn_constant_dimension_min_std() {
        // All states identical in dim 0 => std → min 1e-10
        let states = vec![vec![5.0, 0.0], vec![5.0, 2.0]];
        let profile = SelfProfile::learn(&states);
        assert!((profile.std_state[0] - 1e-10).abs() < 1e-15);
        assert!(profile.std_state[1] > 1e-10);
    }

    #[test]
    #[should_panic(expected = "cannot learn from empty state set")]
    fn test_learn_empty_panics() {
        let _ = SelfProfile::learn(&[]);
    }

    #[test]
    #[should_panic(expected = "inconsistent state dimensionality")]
    fn test_learn_inconsistent_dim_panics() {
        let _ = SelfProfile::learn(&[vec![0.0], vec![1.0, 2.0]]);
    }

    // -----------------------------------------------------------------------
    // Self / non-self discrimination
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_self_accepts_normal() {
        let profile = SelfProfile::learn(&[vec![0.0, 0.0], vec![1.0, 1.0], vec![2.0, 2.0]]);
        assert!(profile.is_self(&[1.0, 1.0]));
        assert!(profile.is_self(&[1.5, 1.5]));
    }

    #[test]
    fn test_is_self_rejects_outlier() {
        let profile = SelfProfile::learn(&[vec![0.0, 0.0], vec![1.0, 1.0], vec![2.0, 2.0]]);
        // mean=1.0, std≈0.816; 10.0 is ~11σ away
        assert!(!profile.is_self(&[10.0, 10.0]));
    }

    #[test]
    fn test_is_self_edge_tolerance() {
        // Exactly at 3σ boundary
        let states = vec![vec![0.0], vec![100.0]];
        let profile = SelfProfile::learn(&states);
        // mean=50, std=50
        // 50 + 3*50 = 200 is exactly at boundary → should be self
        assert!(profile.is_self(&[200.0]));
        // 201 is just beyond boundary → not self
        assert!(!profile.is_self(&[201.0]));
    }

    // -----------------------------------------------------------------------
    // Anomaly scoring
    // -----------------------------------------------------------------------

    #[test]
    fn test_anomaly_score_zero_for_self() {
        let profile = SelfProfile::learn(&[vec![0.0], vec![1.0], vec![2.0]]);
        // mean=1, std≈0.816; at mean → 0
        let score = profile.anomaly_score(&[1.0]);
        assert!((score - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_anomaly_score_positive_for_outlier() {
        let profile = SelfProfile::learn(&[vec![0.0], vec![1.0], vec![2.0]]);
        let score = profile.anomaly_score(&[100.0]);
        assert!(score > 0.0);
    }

    #[test]
    fn test_anomaly_score_non_negative() {
        let profile = SelfProfile::learn(&[vec![0.0, 0.0], vec![1.0, 1.0], vec![2.0, 2.0]]);
        for v in &[0.0, 1.0, 1.5, 5.0, -10.0] {
            let score = profile.anomaly_score(&[*v, *v]);
            assert!(score >= 0.0, "score should never be negative, got {}", score);
        }
    }

    // -----------------------------------------------------------------------
    // IntrusionDetector: individual agent check
    // -----------------------------------------------------------------------

    #[test]
    fn test_detector_clean_states() {
        let profile = SelfProfile::learn(&[vec![0.0, 0.0], vec![1.0, 1.0], vec![2.0, 2.0]]);
        let mut detector = IntrusionDetector::new(profile, 0.5);
        let detections = detector.check(&[vec![1.0, 1.0], vec![1.5, 1.5]]);
        assert_eq!(detections.len(), 2);
        assert!(!detections[0].detected);
        assert!(!detections[1].detected);
    }

    #[test]
    fn test_detector_flags_outlier() {
        let profile = SelfProfile::learn(&[vec![0.0, 0.0], vec![1.0, 1.0], vec![2.0, 2.0]]);
        let mut detector = IntrusionDetector::new(profile, 0.5);
        let detections = detector.check(&[vec![100.0, 100.0]]);
        assert!(detections[0].detected);
        assert!(detections[0].confidence > 0.0);
        assert!(detections[0].anomaly_score > 0.5);
        assert_eq!(detections[0].tick, 1);
    }

    #[test]
    fn test_detector_tick_increments() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let mut detector = IntrusionDetector::new(profile, 10.0);
        let a = detector.check(&[vec![0.0]]);
        let b = detector.check(&[vec![0.0]]);
        assert_eq!(a[0].tick, 1);
        assert_eq!(b[0].tick, 2);
    }

    // -----------------------------------------------------------------------
    // Correlation-based detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_correlation_detection_clean() {
        let states = vec![vec![1.0, 2.0], vec![1.1, 2.1], vec![0.9, 1.9]];
        let profile = SelfProfile::learn(&states);
        let mut detector = IntrusionDetector::new(profile, 5.0);
        // Same pattern → high correlation → no detection
        let d = detector.check_correlation(&states);
        assert!(!d.detected);
    }

    #[test]
    fn test_correlation_detection_drop() {
        let normal = vec![vec![1.0, 2.0], vec![1.1, 2.1], vec![0.9, 1.9]];
        let profile = SelfProfile::learn(&normal);
        let mut detector = IntrusionDetector::new(profile, 1.0);
        // Wildly different states → zero correlation → drop > threshold
        let anomalous = vec![vec![-100.0, 200.0], vec![100.0, -200.0], vec![0.0, 0.0]];
        let d = detector.check_correlation(&anomalous);
        assert!(d.detected, "correlation drop should be detected");
    }

    // -----------------------------------------------------------------------
    // Immune response
    // -----------------------------------------------------------------------

    #[test]
    fn test_response_identifies_anomalous_agents() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let detector = IntrusionDetector::new(profile, 0.5);
        let detections = vec![
            Detection { detected: false, confidence: 0.0, anomaly_score: 0.0, tick: 1 },
            Detection { detected: true, confidence: 0.9, anomaly_score: 10.0, tick: 1 },
            Detection { detected: true, confidence: 0.8, anomaly_score: 5.0, tick: 1 },
        ];
        let resp = detector.response(&detections);
        assert_eq!(resp.quarantined_agents, vec![1, 2]);
        assert!(!resp.is_clean());
    }

    #[test]
    fn test_response_clean() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let detector = IntrusionDetector::new(profile, 10.0);
        let detections = vec![
            Detection { detected: false, confidence: 0.0, anomaly_score: 0.0, tick: 1 },
        ];
        let resp = detector.response(&detections);
        assert!(resp.is_clean());
        assert!(resp.quarantined_agents.is_empty());
    }

    #[test]
    fn test_quarantine_zeroes_agents() {
        let mut states = vec![vec![1.0, 2.0], vec![3.0, 4.0], vec![5.0, 6.0]];
        let resp = ImmuneResponse {
            quarantined_agents: vec![0, 2],
            anomaly_scores: vec![10.0, 20.0],
        };
        resp.quarantine(&mut states);
        assert_eq!(states[0], vec![0.0, 0.0]);
        assert_eq!(states[1], vec![3.0, 4.0]); // untouched
        assert_eq!(states[2], vec![0.0, 0.0]);
    }

    #[test]
    fn test_quarantine_out_of_bounds_ignored() {
        let mut states = vec![vec![1.0]];
        let resp = ImmuneResponse {
            quarantined_agents: vec![99], // out of bounds
            anomaly_scores: vec![10.0],
        };
        resp.quarantine(&mut states); // should not panic
        assert_eq!(states[0], vec![1.0]);
    }

    // -----------------------------------------------------------------------
    // False positive rate
    // -----------------------------------------------------------------------

    #[test]
    fn test_fpr_initial_zero() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let detector = IntrusionDetector::new(profile, 0.5);
        assert_eq!(detector.false_positive_rate(), 0.0);
    }

    #[test]
    fn test_fpr_after_detections() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let mut detector = IntrusionDetector::new(profile, 0.5);
        // Two clean, two anomalous
        detector.check(&[vec![0.0], vec![0.0]]);
        detector.check(&[vec![100.0], vec![200.0]]);
        let fpr = detector.false_positive_rate();
        // history = [0.0, 0.0, ~97, ~197] → 2/4 = 0.5
        assert!((fpr - 0.5).abs() < 0.01);
    }

    // -----------------------------------------------------------------------
    // Multi-agent detection (integration)
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_agent_detection() {
        // 3 agents, 2-dimensional state
        let normal = vec![
            vec![10.0, 20.0],
            vec![11.0, 21.0],
            vec![9.0, 19.0],
            vec![10.5, 20.5],
        ];
        let profile = SelfProfile::learn(&normal);
        let mut detector = IntrusionDetector::new(profile, 1.0);

        // Two normal agents, one anomalous
        let states = vec![
            vec![10.0, 20.0],  // normal
            vec![1000.0, -500.0],  // anomalous
            vec![9.5, 19.5],  // normal
        ];
        let detections = detector.check(&states);
        assert_eq!(detections.len(), 3);
        assert!(!detections[0].detected, "agent 0 should be clean");
        assert!(detections[1].detected, "agent 1 should be flagged");
        assert!(!detections[2].detected, "agent 2 should be clean");

        let resp = detector.response(&detections);
        assert_eq!(resp.quarantined_agents, vec![1]);

        let mut mutable_states = states.clone();
        resp.quarantine(&mut mutable_states);
        assert_eq!(mutable_states[0], vec![10.0, 20.0]); // untouched
        assert_eq!(mutable_states[1], vec![0.0, 0.0]); // zeroed
        assert_eq!(mutable_states[2], vec![9.5, 19.5]); // untouched
    }

    #[test]
    fn test_confidence_increases_with_severity() {
        let profile = SelfProfile::learn(&[vec![0.0]]);
        let mut detector = IntrusionDetector::new(profile, 0.5);
        let mild = detector.check(&[vec![10.0]]);
        let severe = detector.check(&[vec![1000.0]]);
        assert!(severe[0].confidence > mild[0].confidence);
    }
}
