//! Build-time fault-injection seam (probeability rule P-d).
//!
//! Compiled in ONLY under the `fault-injection` feature. The release binary
//! published to crates.io is built without it, so the seam is entirely absent:
//! no live trigger, no runtime branch, nothing an operator can flip. That
//! absence is what lets the release self-check report S-01/S-02/X-02 as honestly
//! not-applicable and X-03 (release posture) as pass.
//!
//! When the feature IS on, `RF_FAULT=<stage>` makes the named stage panic at its
//! seam, so the totality wrapper in `main` can be shown to convert a real
//! per-stage fault into a total error envelope (exit 7, INTERNAL, the
//! full seven keys) instead of an unmediated crash. A panic — not a returned
//! Err — is injected on purpose: the unmediated-crash path is exactly what
//! totality must catch, so that is what the seam must exercise.

/// The stages that carry an injection seam: the eight stages of
/// `diagnosis_order`, in that order. The conformance verb folds over this list.
pub const STAGES: [&str; 8] = [
    "bootstrap_mode",
    "global_flag",
    "command_path",
    "command_flag",
    "value_validation",
    "required_argument",
    "semantic_resolution",
    "execution",
];

/// True iff the seam is compiled into this binary. Drives the conformance verb's
/// choice between running the totality probes and reporting them not-applicable.
#[cfg(feature = "fault-injection")]
pub const SEAM_PRESENT: bool = true;
#[cfg(not(feature = "fault-injection"))]
pub const SEAM_PRESENT: bool = false;

/// Panic if `RF_FAULT` names this stage. A no-op (and fully compiled out) unless
/// the `fault-injection` feature is on.
#[cfg(feature = "fault-injection")]
pub fn maybe_fault(stage: &str) {
    if let Ok(want) = std::env::var("RF_FAULT") {
        if want == stage {
            panic!("injected fault at stage '{stage}' (RF_FAULT)");
        }
    }
}

#[cfg(not(feature = "fault-injection"))]
#[inline(always)]
pub fn maybe_fault(_stage: &str) {}
