import json
import tempfile
import unittest
from pathlib import Path

from aether_scout.cli import main
from aether_scout.scoring import score_surface


class ScoringTests(unittest.TestCase):
    def test_scores_high_medium_low_and_fatal(self):
        high = score_surface({
            "surface_type": "rag_chat",
            "url": "https://app.example.com/chat",
            "indicators": ["chat", "sources", "workspace"],
            "evidence_metadata": {"auth_required": True, "program_policy": "allowed", "api_schema_confidence": 0.8},
        })
        medium = score_surface({"surface_type": "ai_chat", "indicators": ["chat"]})
        low = score_surface({"surface_type": "unknown_ai_surface", "indicators": []})
        fatal = score_surface({"surface_type": "ai_chat", "scope_status": "rejected", "indicators": ["chat"]})

        self.assertGreaterEqual(high["viability_score"], 0.7)
        self.assertGreater(medium["viability_score"], low["viability_score"])
        self.assertIn("weak_indicators", low["blockers"])
        self.assertEqual(fatal["viability_score"], 0.0)
        self.assertEqual(fatal["recommended_next_step"], "do_not_test")

    def test_cli_scores_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            surfaces = Path(tmp) / "surfaces.jsonl"
            out = Path(tmp) / "scored.jsonl"
            surfaces.write_text(json.dumps({"surface_type": "ai_chat", "indicators": ["chat"], "url": "https://app.example.com/chat"}) + "\n", encoding="utf-8")

            code = main(["score-surfaces", "--surfaces", str(surfaces), "--out", str(out)])

            self.assertEqual(code, 0)
            row = json.loads(out.read_text(encoding="utf-8").strip())
            self.assertIn("viability_score", row)
            self.assertIn("recommended_next_step", row)


if __name__ == "__main__":
    unittest.main()
