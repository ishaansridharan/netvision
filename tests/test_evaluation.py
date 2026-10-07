"""Evaluation metrics definitions and the harness end to end."""

import json

import pytest

from evaluation.metrics import AlertPoint, Incident, merge, score


def _a(t, ts):
    return AlertPoint(t, ts)


def test_tp_fp_secondary_and_latency():
    incs = [Incident("PORT_SCAN", 100, 130), Incident("SYN_FLOOD", 200, 230)]
    alerts = [
        _a("PORT_SCAN", 103),       # TP, latency 3
        _a("PORT_SCAN", 120),       # TP (same incident)
        _a("PORT_SCAN", 133),       # TP within 5 s grace
        _a("PORT_SCAN", 400),       # FP
        _a("TRAFFIC_SPIKE", 205),   # secondary (inside a SYN flood)
    ]
    s = score(alerts, incs, 0, 600, grace_s=5, bin_s=10).to_dict()
    ps = s["per_type"]["PORT_SCAN"]
    assert (ps["true_positives"], ps["false_positives"], ps["detected"]) == (3, 1, 1)
    assert ps["precision"] == 0.75 and ps["recall"] == 1.0
    assert ps["latency_median_s"] == 3.0
    sf = s["per_type"]["SYN_FLOOD"]
    assert sf["recall"] == 0.0 and sf["precision"] is None
    assert s["per_type"]["TRAFFIC_SPIKE"]["secondary_alerts"] == 1
    assert s["per_type"]["TRAFFIC_SPIKE"]["precision"] is None
    assert s["overall"]["recall"] == 0.5


def test_fpr_uses_normal_bins_only():
    incs = [Incident("PORT_SCAN", 0, 9)]       # bins 0–1 are attack (with grace)
    alerts = [_a("ARP_ANOMALY", 55), _a("ARP_ANOMALY", 57), _a("ARP_ANOMALY", 75)]
    s = score(alerts, incs, 0, 100, grace_s=5, bin_s=10).to_dict()
    arp = s["per_type"]["ARP_ANOMALY"]
    assert arp["normal_bins"] == 8 and arp["fp_bins"] == 2
    assert arp["fpr"] == 0.25


def test_merge_sums_raw_counts():
    a = score([_a("PORT_SCAN", 5)], [Incident("PORT_SCAN", 0, 10)], 0, 100)
    b = score([_a("PORT_SCAN", 50)], [Incident("PORT_SCAN", 0, 10)], 0, 100)
    m = merge([a, b]).to_dict()["per_type"]["PORT_SCAN"]
    assert (m["incidents"], m["detected"], m["true_positives"], m["false_positives"]) == (2, 1, 1, 1)


@pytest.mark.slow
def test_harness_end_to_end(tmp_path, monkeypatch):
    from evaluation import run_eval
    from evaluation.sample_capture import generate

    pcap = tmp_path / "s.pcap"
    generate(str(pcap), duration=60, seed=3, burst=(35, 45))
    monkeypatch.setattr(run_eval, "RESULTS_DIR", str(tmp_path / "results"))
    assert run_eval.main([str(pcap), "--name", "t"]) == 0

    out = tmp_path / "results" / "t"
    summary = json.loads((out / "summary.json").read_text())
    for mode in ("static", "adaptive"):
        spike = summary["results"][mode]["per_type"]["TRAFFIC_SPIKE"]
        assert spike["incidents"] == 1
    assert summary["performance"]["parse_pps"] > 0
    for f in ("metrics.csv", "report.md", "quality.png", "fpr.png", "latency.png",
              "timeline_s.png", "alerts_static.csv"):
        assert (out / f).exists(), f
