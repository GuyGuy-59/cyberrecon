"""Shared helpers for scan modules."""


def run_safe(logger, label, fn, *args, **kwargs):
    """Call ``fn(*args, **kwargs)``; log failure and continue."""
    try:
        fn(*args, **kwargs)
    except Exception as e:
        logger.error("%s failed: %s", label, e)


def run_safe_steps(logger, steps):
    """``steps`` is a list of ``(label, fn, args_tuple)``."""
    for label, fn, args in steps:
        run_safe(logger, label, fn, *args)
