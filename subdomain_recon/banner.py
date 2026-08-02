"""
ASCII banner, printed at startup -- built from a small hand-rolled 5x5
block font (no external dependency like pyfiglet needed), with a 24-bit
ANSI color palette and a drop-shadow effect on the block letters.
"""
from __future__ import annotations

FONT: dict[str, list[str]] = {
    "A": [".###.", "#...#", "#####", "#...#", "#...#"],
    "B": ["####.", "#...#", "####.", "#...#", "####."],
    "C": [".####", "#....", "#....", "#....", ".####"],
    "D": ["####.", "#...#", "#...#", "#...#", "####."],
    "E": ["#####", "#....", "###..", "#....", "#####"],
    "F": ["#####", "#....", "###..", "#....", "#...."],
    "G": [".####", "#....", "#.###", "#...#", ".####"],
    "H": ["#...#", "#...#", "#####", "#...#", "#...#"],
    "I": ["#####", "..#..", "..#..", "..#..", "#####"],
    "J": ["..###", "...#.", "...#.", "#..#.", ".##.."],
    "K": ["#...#", "#..#.", "###..", "#..#.", "#...#"],
    "L": ["#....", "#....", "#....", "#....", "#####"],
    "M": ["#...#", "##.##", "#.#.#", "#...#", "#...#"],
    "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#"],
    "O": [".###.", "#...#", "#...#", "#...#", ".###."],
    "P": ["####.", "#...#", "####.", "#....", "#...."],
    "Q": [".###.", "#...#", "#.#.#", "#..#.", ".##.#"],
    "R": ["####.", "#...#", "####.", "#..#.", "#...#"],
    "S": [".####", "#....", ".###.", "....#", "####."],
    "T": ["#####", "..#..", "..#..", "..#..", "..#.."],
    "U": ["#...#", "#...#", "#...#", "#...#", ".###."],
    "V": ["#...#", "#...#", "#...#", ".#.#.", "..#.."],
    "W": ["#...#", "#...#", "#.#.#", "##.##", "#...#"],
    "X": ["#...#", ".#.#.", "..#..", ".#.#.", "#...#"],
    "Y": ["#...#", ".#.#.", "..#..", "..#..", "..#.."],
    "Z": ["#####", "...#.", "..#..", ".#...", "#####"],
    "0": [".###.", "#...#", "#...#", "#...#", ".###."],
    "1": ["..#..", ".##..", "..#..", "..#..", "#####"],
    "2": [".###.", "#...#", "...#.", "..#..", "#####"],
    "3": ["####.", "....#", "..##.", "....#", "####."],
    "4": ["#..#.", "#..#.", "#####", "...#.", "...#."],
    "5": ["#####", "#....", "####.", "....#", "####."],
    "6": [".###.", "#....", "####.", "#...#", ".###."],
    "7": ["#####", "....#", "...#.", "..#..", "..#.."],
    "8": [".###.", "#...#", ".###.", "#...#", ".###."],
    "9": [".###.", "#...#", ".####", "....#", ".###."],
    " ": [".....", ".....", ".....", ".....", "....."],
}

COLOR_BANNER = "#FF2D55"
COLOR_SHADOW = "#B00020"
COLOR_SUBTITLE = "#D1D5DB"
COLOR_VERSION = "#FF8C00"
COLOR_DIVIDER = "#4B5563"
_RESET = "\033[0m"


def _hex_to_ansi_fg(hex_color: str) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i + 2], 16) for i in (0, 2, 4))
    return f"\033[38;2;{r};{g};{b}m"


def _glyph_grid(text: str) -> list[list[bool]]:
    text = text.upper()
    rows: list[list[bool]] = [[] for _ in range(5)]
    for ch in text:
        glyph = FONT.get(ch, FONT[" "])
        for i in range(5):
            rows[i].extend(c == "#" for c in glyph[i])
            rows[i].append(False)
    return rows


def render(text: str, block: str = "\u2588", shadow: bool = True) -> tuple[str, int]:
    grid = _glyph_grid(text)
    height = len(grid)
    width = len(grid[0]) if grid else 0
    canvas_h = height + (1 if shadow else 0)
    canvas_w = width + (1 if shadow else 0)

    main_fg = _hex_to_ansi_fg(COLOR_BANNER)
    shadow_fg = _hex_to_ansi_fg(COLOR_SHADOW)

    lines = []
    for r in range(canvas_h):
        chars = []
        for c in range(canvas_w):
            is_main = r < height and c < width and grid[r][c]
            is_shadow = (
                shadow and r >= 1 and c >= 1
                and (r - 1) < height and (c - 1) < width
                and grid[r - 1][c - 1]
                and not is_main
            )
            if is_main:
                chars.append(f"{main_fg}{block}{_RESET}")
            elif is_shadow:
                chars.append(f"{shadow_fg}{block}{_RESET}")
            else:
                chars.append(" ")
        lines.append("".join(chars))
    return "\n".join(lines), canvas_w


def print_banner(name: str, version: str, tagline: str = "") -> None:
    art, width = render(name)
    print(art)

    divider_fg = _hex_to_ansi_fg(COLOR_DIVIDER)
    subtitle_fg = _hex_to_ansi_fg(COLOR_SUBTITLE)
    version_fg = _hex_to_ansi_fg(COLOR_VERSION)

    if tagline:
        print(f"{subtitle_fg}{tagline:>{width}}{_RESET}")
    print(f"{version_fg}{'v' + version:>{width}}{_RESET}")
    print(f"{divider_fg}{'-' * width}{_RESET}")
    print()


# --------------------------------------------------------------------- #
# Dedicated "Mr. Cool" banner -- hand-drawn box-art block letters (in the
# style of Sublist3r/subfinder-type tool banners), plus a boxed metadata
# panel (author / version / engine / mode / status).
# --------------------------------------------------------------------- #
_MR_COOL_ART = r"""
   ███╗   ███╗ ██████╗       ██████╗ ██████╗  ██████╗ ██╗     
   ████╗ ████║ ██╔══██╗     ██╔════╝██╔═══██╗██╔═══██╗██║     
   ██╔████╔██║ ██████╔╝     ██║     ██║   ██║██║   ██║██║     
   ██║╚██╔╝██║ ██╔══██╗     ██║     ██║   ██║██║   ██║██║     
   ██║ ╚═╝ ██║ ██║  ██║     ╚██████╗╚██████╔╝╚██████╔╝███████╗
   ╚═╝     ╚═╝ ╚═╝  ╚═╝      ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝"""

COLOR_MRCOOL_RED = "#FF3B3B"
COLOR_MRCOOL_ORANGE = "#FF8C00"
COLOR_MRCOOL_GRAY = "#8B949E"


def print_mr_cool_banner(version: str, python_version: str, mode: str, status: str = "READY") -> None:
    """Prints the dedicated "Mr. Cool" banner: block-letter logo + a boxed
    metadata panel (Author / Version / Engine / Mode / Status), colored
    like a classic red-on-dark recon-tool banner."""
    red = _hex_to_ansi_fg(COLOR_MRCOOL_RED)
    orange = _hex_to_ansi_fg(COLOR_MRCOOL_ORANGE)
    gray = _hex_to_ansi_fg(COLOR_MRCOOL_GRAY)

    width = 63
    top_border = "\u2554" + "\u2550" * width + "\u2557"
    mid_divider = "\u2500" * (width + 2)

    print(f"{red}{top_border}{_RESET}")
    for line in _MR_COOL_ART.splitlines():
        if line:
            print(f"{red}{line}{_RESET}")
    print(f"{orange}{'ADVANCED RECON FRAMEWORK':>{width // 2 + 15}}{_RESET}")
    print(f"{gray}{mid_divider}{_RESET}")
    print(f"{gray} Author      : {_RESET}{orange}Sazzadul{_RESET}")
    print(f"{gray} Version     : {_RESET}{orange}v{version}{_RESET}")
    print(f"{gray} Engine      : {_RESET}{orange}Python {python_version}{_RESET}")
    print(f"{gray} Mode        : {_RESET}{orange}{mode}{_RESET}")
    print(f"{gray} Status      : {_RESET}{orange}{status}{_RESET}")
    print(f"{gray}{mid_divider}{_RESET}")
    print()
