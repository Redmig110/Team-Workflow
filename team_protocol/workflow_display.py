from __future__ import annotations


STEP_DEFINITIONS = (
    ("old_login", "旧号登录"),
    ("invite", "邀请新号"),
    ("old_leave", "旧号退出"),
    ("new_login", "新号注册"),
    ("pat", "创建令牌"),
    ("cpa", "生成 CPA"),
    ("push", "推送 CPA"),
    ("push_sub2api", "推送 Sub2API"),
)

STEP_STATE_TEXT = {
    "pending": "待执行",
    "active": "执行中",
    "done": "完成",
    "skipped": "跳过",
    "error": "失败",
}

STEP_IDS = frozenset(step for step, _ in STEP_DEFINITIONS)
TERMINAL_STEP_STATES = frozenset({"done", "skipped", "error"})


def log_level(message: str) -> str:
    lowered = message.casefold()
    if "[error]" in lowered or "failed" in lowered:
        return "error"
    if "[warn]" in lowered or "[!]" in lowered:
        return "warn"
    if "[success]" in lowered or "[+]" in lowered:
        return "success"
    return "info"


def is_routine_log(message: str) -> bool:
    normalized = message.lstrip().upper()
    return normalized.startswith("[INFO]") or normalized.startswith("[DEBUG]")
