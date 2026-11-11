import os
from typing import Dict


class AgentFrameworkRepoLoader:
    """
    Loads the declarative Agent Framework files from `agent_framework/`:
    - base_system_prompt.md (Role & Guardrails)
    - skills/content-analysis.md (Psychological urgency/fear rules)
    - skills/scam-scoring.md (Final risk weighting rubric)
    """

    def __init__(self, repo_dir: str | None = None) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.repo_dir = repo_dir or os.path.join(base_dir, "agent_framework")

    def _read_md(self, rel_path: str) -> str:
        full_path = os.path.join(self.repo_dir, rel_path)
        with open(full_path, "r", encoding="utf-8") as f:
            return f.read().strip()

    def load_all(self) -> Dict[str, str]:
        return {
            "base_system_prompt": self._read_md("base_system_prompt.md"),
            "content_analysis_skill": self._read_md("skills/content-analysis.md"),
            "scam_scoring_skill": self._read_md("skills/scam-scoring.md"),
        }

    def assemble_system_instruction(self) -> str:
        docs = self.load_all()
        return (
            f"{docs['base_system_prompt']}\n\n"
            f"---\n{docs['content_analysis_skill']}\n\n"
            f"---\n{docs['scam_scoring_skill']}"
        )


framework_loader = AgentFrameworkRepoLoader()

