"""命令行入口占位——CLI 闭环由 WP-10 交付,run/tui 子命令由 WP-04/WP-09 接入。"""

from __future__ import annotations

import sys

from kalicode import __app_name__, __version__


def main() -> int:
    print(f"{__app_name__} {__version__}(pre-alpha,骨架已就位,WP-01 起开发)")
    print("进度见 docs/HANDOVER.md;工作包台账见 docs/wp-ledger.md。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
