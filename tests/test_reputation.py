import pytest

from proxim import GOOD, BAD, JsonFileLedger, ReputationLedger


def test_cold_start_returns_prior():
    led = ReputationLedger(prior_mean=0.5)
    score = led.score("px_unknown")
    assert score.is_cold_start
    assert score.value == pytest.approx(0.5)
    assert score.sample_count == 0


def test_all_good_trends_high():
    led = ReputationLedger()
    for _ in range(20):
        led.record_success("px_a", at=1000.0)
    score = led.score("px_a", now=1000.0)
    assert score.value > 0.9
    assert score.sample_count == 20


def test_all_bad_trends_low():
    led = ReputationLedger()
    for _ in range(20):
        led.record_failure("px_a", at=1000.0)
    score = led.score("px_a", now=1000.0)
    assert score.value < 0.1


def test_single_outcome_does_not_slam_to_extreme():
    led = ReputationLedger(prior_mean=0.5, prior_strength=2.0)
    led.record_success("px_a", at=1000.0)
    score = led.score("px_a", now=1000.0)
    # one success: (0.5*2 + 1) / (2 + 1) = 2/3
    assert score.value == pytest.approx(2 / 3, abs=1e-6)


def test_time_decay_fades_old_evidence():
    led = ReputationLedger(half_life_days=30.0, prior_strength=2.0)
    # one bad event long ago
    led.record_failure("px_a", at=0.0)
    one_year = 365 * 86400.0
    score = led.score("px_a", now=one_year)
    # heavily decayed -> drifts back toward the 0.5 prior
    assert score.value > 0.45


def test_recent_outweighs_old():
    led = ReputationLedger(half_life_days=10.0)
    led.record_failure("px_a", at=0.0)          # old bad
    led.record_success("px_a", at=100 * 86400.0)  # recent good
    score = led.score("px_a", now=100 * 86400.0)
    assert score.value > 0.6


def test_outcome_is_clamped():
    led = ReputationLedger()
    ev = led.record("px_a", 5.0)
    assert ev.outcome == 1.0
    ev2 = led.record("px_a", -3.0)
    assert ev2.outcome == 0.0


def test_invalid_params():
    with pytest.raises(ValueError):
        ReputationLedger(half_life_days=0)
    with pytest.raises(ValueError):
        ReputationLedger(prior_mean=2.0)


def test_json_file_ledger_persists(tmp_path):
    path = tmp_path / "rep.json"
    led = JsonFileLedger(path, half_life_days=15.0)
    led.record_success("px_a", at=1000.0)
    led.record_failure("px_a", at=1001.0)

    reloaded = JsonFileLedger(path)
    assert reloaded.half_life_days == 15.0
    assert len(reloaded.events_for("px_a")) == 2
