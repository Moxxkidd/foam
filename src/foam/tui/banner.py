"""大号字标渲染:内置 5 行点阵字体,按 ``__app_name__`` 动态生成。

历史注记(2026-09-11):原品牌纪律(AGENTS.md §0 / WP-09 验收 5)已于
2026-08-27 退役(见 AGENTS.md §0 历史注记);字标内容只能来自 ``__app_name__``
常量、本模块不出现任何品牌字符串的机制保留,作为品牌防回归契约继续生效
(有测试锁定)。收录 A-Z/0-9/空格/连字符的 5x5 点阵字形;小写自动转大写;
未收录字符渲染为「?」块——未来改名到任何拉丁字母名字都无需改本文件。
"""

from __future__ import annotations

import math

from rich.text import Text

GLYPH_ROWS = 5

#: 5 行点阵字形表(每字形宽度 ≤5 列,渲染时行间纵向对齐、字间两空格)。
_GLYPHS: dict[str, tuple[str, ...]] = {
    "A": (" ███ ", "█   █", "█████", "█   █", "█   █"),
    "B": ("████ ", "█   █", "████ ", "█   █", "████ "),
    "C": (" ████", "█    ", "█    ", "█    ", " ████"),
    "D": ("████ ", "█   █", "█   █", "█   █", "████ "),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "F": ("█████", "█    ", "████ ", "█    ", "█    "),
    "G": (" ████", "█    ", "█  ██", "█   █", " ████"),
    "H": ("█   █", "█   █", "█████", "█   █", "█   █"),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "J": ("  ███", "   █ ", "   █ ", "█  █ ", " ██  "),
    "K": ("█   █", "█  █ ", "███  ", "█  █ ", "█   █"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "M": ("█   █", "██ ██", "█ █ █", "█   █", "█   █"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "O": (" ███ ", "█   █", "█   █", "█   █", " ███ "),
    "P": ("████ ", "█   █", "████ ", "█    ", "█    "),
    "Q": (" ███ ", "█   █", "█ █ █", "█  █ ", " ██ █"),
    "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
    "S": (" ████", "█    ", " ███ ", "    █", "████ "),
    "T": ("█████", "  █  ", "  █  ", "  █  ", "  █  "),
    "U": ("█   █", "█   █", "█   █", "█   █", " ███ "),
    "V": ("█   █", "█   █", "█   █", " █ █ ", "  █  "),
    "W": ("█   █", "█   █", "█ █ █", "██ ██", "█   █"),
    "X": ("█   █", " █ █ ", "  █  ", " █ █ ", "█   █"),
    "Y": ("█   █", " █ █ ", "  █  ", "  █  ", "  █  "),
    "Z": ("█████", "   █ ", "  █  ", " █   ", "█████"),
    "0": (" ███ ", "█  ██", "█ █ █", "██  █", " ███ "),
    "1": ("  █  ", " ██  ", "  █  ", "  █  ", "█████"),
    "2": (" ███ ", "█   █", "  ██ ", " █   ", "█████"),
    "3": ("████ ", "    █", " ███ ", "    █", "████ "),
    "4": ("█  █ ", "█  █ ", "█████", "   █ ", "   █ "),
    "5": ("█████", "█    ", "████ ", "    █", "████ "),
    "6": (" ███ ", "█    ", "████ ", "█   █", " ███ "),
    "7": ("█████", "   █ ", "  █  ", " █   ", "█    "),
    "8": (" ███ ", "█   █", " ███ ", "█   █", " ███ "),
    "9": (" ███ ", "█   █", " ████", "    █", " ███ "),
    "-": ("     ", "     ", "████ ", "     ", "     "),
    " ": ("   ", "   ", "   ", "   ", "   "),
}

#: 未收录字符的兜底字形(问号块)。
_FALLBACK: tuple[str, ...] = (" ███ ", "█   █", "  ██ ", "     ", "  █  ")


def render_wordmark(text: str) -> list[str]:
    """把文本渲染为大号字标,返回 5 行字符串(行间已是视觉对齐的等宽块)。"""
    rows = [""] * GLYPH_ROWS
    for ch in text.upper():
        glyph = _GLYPHS.get(ch, _FALLBACK)
        for i in range(GLYPH_ROWS):
            rows[i] += glyph[i] + "  "
    return [row.rstrip() for row in rows]


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    cleaned = value.lstrip("#")
    return (int(cleaned[0:2], 16), int(cleaned[2:4], 16), int(cleaned[4:6], 16))


def _lerp_rgb(
    c1: tuple[int, int, int], c2: tuple[int, int, int], t: float
) -> tuple[int, int, int]:
    ratio = _clamp(t, 0.0, 1.0)
    return tuple(round(a + (b - a) * ratio) for a, b in zip(c1, c2, strict=True))  # type: ignore[return-value]


def _sample_gradient(
    stops: tuple[tuple[float, tuple[int, int, int]], ...], t: float
) -> tuple[int, int, int]:
    clamped = _clamp(t, stops[0][0], stops[-1][0])
    for idx in range(len(stops) - 1):
        p0, c0 = stops[idx]
        p1, c1 = stops[idx + 1]
        if clamped <= p1:
            span = max(1e-6, p1 - p0)
            return _lerp_rgb(c0, c1, (clamped - p0) / span)
    return stops[-1][1]


_FG_WAVE_STOPS: tuple[tuple[float, tuple[int, int, int]], ...] = (
    (0.00, _hex_to_rgb("#0284c7")),
    (0.35, _hex_to_rgb("#06b6d4")),
    (0.70, _hex_to_rgb("#2dd4bf")),
    (1.00, _hex_to_rgb("#99f6e4")),
)
_CREST_WHITE = _hex_to_rgb("#ecfeff")
_SHADOW_WAVE_STOPS: tuple[tuple[float, tuple[int, int, int]], ...] = (
    (0.00, _hex_to_rgb("#134e5e")),
    (0.50, _hex_to_rgb("#0e7490")),
    (1.00, _hex_to_rgb("#1e88a8")),
)
_SHADOW_CHARS: dict[tuple[int, int, int], str] = {
    (0, 1, 0): "╗",
    (0, 1, 1): "║",
    (1, 0, 0): "╚",
    (1, 0, 1): "═",
    (0, 0, 1): "╝",
    (1, 1, 1): "╔",
    (1, 1, 0): "╔",
}


def render_3d_wordmark(
    text: str, *, scale_x: int = 2, letter_gap: int = 3
) -> list[list[tuple[str, str]]]:
    """构建带 1 格右下立体投影的二维单元格网格: ``(char, kind)``。"""
    fg_rows: list[list[bool]] = [[] for _ in range(GLYPH_ROWS)]
    chars = list(text.upper())
    for idx, ch in enumerate(chars):
        glyph = _GLYPHS.get(ch, _FALLBACK)
        for r in range(GLYPH_ROWS):
            if idx > 0:
                fg_rows[r].extend([False] * letter_gap)
            for pixel in glyph[r]:
                fg_rows[r].extend([pixel != " "] * scale_x)

    width = max((len(row) for row in fg_rows), default=0)
    grid: list[list[tuple[str, str]]] = []
    for r in range(GLYPH_ROWS + 1):
        out_row: list[tuple[str, str]] = []
        for c in range(width + 1):
            if r < GLYPH_ROWS and c < width and fg_rows[r][c]:
                out_row.append(("█", "fg"))
                continue
            has_up = 1 if (r > 0 and c < width and fg_rows[r - 1][c]) else 0
            has_left = 1 if (c > 0 and r < GLYPH_ROWS and fg_rows[r][c - 1]) else 0
            has_diag = 1 if (r > 0 and c > 0 and fg_rows[r - 1][c - 1]) else 0
            shadow = _SHADOW_CHARS.get((has_up, has_left, has_diag))
            if shadow is not None:
                out_row.append((shadow, "shadow"))
            else:
                out_row.append((" ", "empty"))
        grid.append(out_row)
    return grid


def _bubble_overlay(
    frame: int, rows: int, cols: int
) -> dict[tuple[int, int], tuple[str, str]]:
    """确定性生成四周与字隙上浮的微气泡(不使用随机数)。"""
    bubbles: dict[tuple[int, int], tuple[str, str]] = {}
    streams = 14
    for idx in range(streams):
        cycle = 18 + (idx * 5) % 13
        active_steps = max(rows, round(cycle * 0.6))
        pos = (frame + (idx * 7) % cycle) % cycle
        if pos >= active_steps:
            continue
        progress = pos / max(1, active_steps - 1) if active_steps > 1 else 0.0
        b_row = round((rows - 1) * (1.0 - progress))
        base_col = round((idx + 0.5) * cols / streams)
        sway = round(math.sin((frame + idx * 3) * 0.25) * 0.8)
        b_col = max(0, min(cols - 1, base_col + sway))
        if progress < 0.35:
            glyph, color = "◦", "#38bdf8"
        elif progress < 0.65:
            glyph, color = "∘", "#56d4dd"
        elif progress < 0.85:
            glyph, color = "°", "#99f6e4"
        else:
            glyph, color = "·", "#64748b"
        bubbles[(b_row, b_col)] = (glyph, color)
    return bubbles


def render_animated_wordmark(
    text: str, frame: int, *, pad_top: int = 2, pad_sides: int = 4
) -> Text:
    """渲染动态海沫波纹 + 立体阴影 + 上浮微气泡大号字标(真彩色 Text)。"""
    raw_grid = render_3d_wordmark(text, scale_x=2, letter_gap=3)
    raw_width = len(raw_grid[0]) if raw_grid else 1
    if len(text) > 5:
        pad_sides = min(pad_sides, 2)
    if raw_width > 66:
        grid = render_3d_wordmark(text, scale_x=1, letter_gap=2)
        if grid and len(grid[0]) + pad_sides * 2 > 76:
            grid = render_3d_wordmark(text, scale_x=1, letter_gap=1)
            pad_sides = 0
    else:
        grid = raw_grid

    word_width = len(grid[0]) if grid else 1
    rows = pad_top + len(grid)
    cols = word_width + pad_sides * 2
    bubbles = _bubble_overlay(frame, rows, cols)
    phase = frame * 0.22

    rendered = Text()
    for row in range(rows):
        for col in range(cols):
            grid_r = row - pad_top
            grid_c = col - pad_sides
            if 0 <= grid_r < len(grid) and 0 <= grid_c < word_width:
                ch, kind = grid[grid_r][grid_c]
            else:
                ch, kind = " ", "empty"

            if kind == "empty":
                bubble = bubbles.get((row, col))
                if bubble is not None:
                    b_ch, b_color = bubble
                    rendered.append(b_ch, style=b_color)
                else:
                    rendered.append(" ")
                continue

            w1 = math.sin(col * 0.22 - row * 0.45 - phase)
            w2 = math.sin(col * 0.48 + row * 0.30 - phase * 1.6) * 0.35
            t = _clamp((w1 + w2 + 1.35) / 2.7, 0.0, 1.0)
            if kind == "fg":
                crest = max(0.0, math.sin(col * 0.14 - row * 0.35 - phase * 0.85)) ** 5
                rgb = _lerp_rgb(
                    _sample_gradient(_FG_WAVE_STOPS, t),
                    _CREST_WHITE,
                    crest * 0.85,
                )
                rendered.append(
                    ch, style=f"bold #{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
                )
            else:
                rgb = _sample_gradient(_SHADOW_WAVE_STOPS, t)
                rendered.append(
                    ch, style=f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"
                )
        if row < rows - 1:
            rendered.append("\n")
    return rendered
