"""Watch a reputation score evolve as feedback accumulates and decays.

Run:  python examples/03_reputation_over_time.py
"""

from proxim import ReputationLedger, GOOD, BAD

DAY = 86_400.0
led = ReputationLedger(half_life_days=30.0)
agent = "px_demo"

print("A new agent starts at the neutral prior:")
print(f"  day   0: score={led.score(agent, now=0).value:.3f}  (cold start)\n")

print("Ten good outcomes on day 0 build a strong reputation:")
for _ in range(10):
    led.record(agent, GOOD, at=0)
print(f"  day   0: score={led.score(agent, now=0).value:.3f}\n")

print("A burst of failures on day 30 tanks it:")
for _ in range(10):
    led.record(agent, BAD, at=30 * DAY)
print(f"  day  30: score={led.score(agent, now=30*DAY).value:.3f}\n")

print("With no new evidence, old outcomes decay and the score drifts toward 0.5:")
for day in (60, 120, 240, 480):
    print(f"  day {day:>3}: score={led.score(agent, now=day*DAY).value:.3f}")
