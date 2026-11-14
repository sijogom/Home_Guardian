"""Home Guardian 앱 아이콘 생성기 — 둥근 방패 + 둥근 집.

정보보안 컨셉(방패) + 홈(집) 조합. 계획서 primary teal #0f766e 사용.
이전 버전은 어깨가 직선이고 하단이 뾰족해 각진 인상을 줬기 때문에,
모든 곡선을 둥글게 깎아 부드러운 인상으로 다시 만든다.

생성물:
- assets/icon.png 1024x1024 (Expo 표준 마스터)
- assets/adaptive-icon-foreground.png 1024x1024 (Android adaptive foreground, safe zone)
- mipmap-*/ic_launcher.webp 5종 (mdpi/hdpi/xhdpi/xxhdpi/xxxhdpi)
- mipmap-*/ic_launcher_round.webp 5종

실행: .\.venv\Scripts\python mobile/assets/make_icon.py
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

MOBILE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = MOBILE_DIR / "assets"
ANDROID_RES = MOBILE_DIR / "android" / "app" / "src" / "main" / "res"

# 계획서 primary teal + 보조색.
TEAL = (15, 118, 110)         # #0f766e
TEAL_DARK = (17, 94, 89)      # #115e59
TEAL_LIGHT = (45, 154, 145)   # 살짝 밝은 보조 톤
WHITE = (255, 255, 255)

DENSITIES = {
    "mdpi": 48,
    "hdpi": 72,
    "xhdpi": 96,
    "xxhdpi": 144,
    "xxxhdpi": 192,
}


def shield_path(cx: float, cy: float, w: float, h: float, *, points: int = 80) -> list[tuple[float, float]]:
    """둥근 방패 외곽선. 위쪽은 큰 곡선 어깨, 좌우는 부드러운 곡선, 아래는 둥근 점.

    매개변수 곡선을 이용해 각진 polygon 대신 매끄러운 closed curve 를 만든다.
    """
    half_w = w / 2
    half_h = h / 2
    # 상단 어깨: 큰 반원에 가까운 호 (좌상 → 우상)
    top_radius_x = half_w
    top_radius_y = half_h * 0.55
    top_arc: list[tuple[float, float]] = []
    for i in range(points + 1):
        t = i / points
        angle = math.pi + t * math.pi  # 180° → 360°
        x = cx + math.cos(angle) * top_radius_x
        y = cy - half_h * 0.45 + math.sin(angle) * top_radius_y
        top_arc.append((x, y))

    # 우측 아래쪽 곡선: 우상 → 하단 점, 부드러운 베지어 (control point inside)
    right_curve: list[tuple[float, float]] = []
    p0 = (cx + half_w, cy - half_h * 0.45)
    p1 = (cx + half_w * 0.92, cy + half_h * 0.4)
    p2 = (cx + half_w * 0.18, cy + half_h * 0.95)
    p3 = (cx, cy + half_h)
    for i in range(1, points + 1):
        t = i / points
        x = (
            (1 - t) ** 3 * p0[0]
            + 3 * (1 - t) ** 2 * t * p1[0]
            + 3 * (1 - t) * t ** 2 * p2[0]
            + t ** 3 * p3[0]
        )
        y = (
            (1 - t) ** 3 * p0[1]
            + 3 * (1 - t) ** 2 * t * p1[1]
            + 3 * (1 - t) * t ** 2 * p2[1]
            + t ** 3 * p3[1]
        )
        right_curve.append((x, y))

    # 좌측 아래쪽 곡선: 하단 점 → 좌상 (우측 대칭)
    left_curve: list[tuple[float, float]] = []
    p0 = (cx, cy + half_h)
    p1 = (cx - half_w * 0.18, cy + half_h * 0.95)
    p2 = (cx - half_w * 0.92, cy + half_h * 0.4)
    p3 = (cx - half_w, cy - half_h * 0.45)
    for i in range(1, points + 1):
        t = i / points
        x = (
            (1 - t) ** 3 * p0[0]
            + 3 * (1 - t) ** 2 * t * p1[0]
            + 3 * (1 - t) * t ** 2 * p2[0]
            + t ** 3 * p3[0]
        )
        y = (
            (1 - t) ** 3 * p0[1]
            + 3 * (1 - t) ** 2 * t * p1[1]
            + 3 * (1 - t) * t ** 2 * p2[1]
            + t ** 3 * p3[1]
        )
        left_curve.append((x, y))

    return top_arc + right_curve + left_curve


def draw_shield(draw: ImageDraw.ImageDraw, cx: float, cy: float, w: float, h: float, *, fill, outline=None, width: int = 0) -> None:
    points = shield_path(cx, cy, w, h)
    draw.polygon(points, fill=fill, outline=outline, width=width)


def draw_house(draw: ImageDraw.ImageDraw, cx: float, cy: float, w: float, h: float, *, fill) -> None:
    """둥근 집. 지붕은 둥근 삼각, 본체는 둥근 사각, 문은 둥근 아치."""
    half_w = w / 2
    half_h = h / 2
    roof_h = h * 0.42
    body_h = h - roof_h

    # 지붕: 부드러운 둥근 삼각형 (3차 베지어로 외곽선)
    apex = (cx, cy - half_h)
    left_eaves = (cx - half_w, cy - half_h + roof_h)
    right_eaves = (cx + half_w, cy - half_h + roof_h)
    # 베지어로 좌측 곡선 (apex → left_eaves)
    points: list[tuple[float, float]] = []
    p0, p3 = apex, left_eaves
    p1 = (apex[0] - half_w * 0.18, apex[1] + roof_h * 0.35)
    p2 = (left_eaves[0] + half_w * 0.18, left_eaves[1] - roof_h * 0.18)
    for i in range(41):
        t = i / 40
        x = (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * p1[0] + 3 * (1 - t) * t ** 2 * p2[0] + t ** 3 * p3[0]
        y = (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * p1[1] + 3 * (1 - t) * t ** 2 * p2[1] + t ** 3 * p3[1]
        points.append((x, y))
    # 처마 가로선 (살짝 안쪽으로 둥글게)
    for i in range(1, 21):
        t = i / 20
        x = left_eaves[0] + (right_eaves[0] - left_eaves[0]) * t
        y = left_eaves[1] + math.sin(t * math.pi) * roof_h * 0.04
        points.append((x, y))
    # 우측 곡선 (right_eaves → apex)
    p0, p3 = right_eaves, apex
    p1 = (right_eaves[0] - half_w * 0.18, right_eaves[1] - roof_h * 0.18)
    p2 = (apex[0] + half_w * 0.18, apex[1] + roof_h * 0.35)
    for i in range(1, 41):
        t = i / 40
        x = (1 - t) ** 3 * p0[0] + 3 * (1 - t) ** 2 * t * p1[0] + 3 * (1 - t) * t ** 2 * p2[0] + t ** 3 * p3[0]
        y = (1 - t) ** 3 * p0[1] + 3 * (1 - t) ** 2 * t * p1[1] + 3 * (1 - t) * t ** 2 * p2[1] + t ** 3 * p3[1]
        points.append((x, y))
    draw.polygon(points, fill=fill)

    # 본체: 모서리가 둥근 사각형
    body_left = cx - half_w * 0.82
    body_right = cx + half_w * 0.82
    body_top = cy - half_h + roof_h - h * 0.02
    body_bottom = cy + half_h
    draw.rounded_rectangle(
        [body_left, body_top, body_right, body_bottom],
        radius=int(min(body_right - body_left, body_bottom - body_top) * 0.18),
        fill=fill,
    )

    # 문: 둥근 아치 (배경색으로 음각)
    door_w = w * 0.24
    door_h = body_h * 0.62
    door_left = cx - door_w / 2
    door_top = body_bottom - door_h
    arch_radius = door_w / 2
    door_points: list[tuple[float, float]] = []
    for i in range(0, 181):
        angle = math.pi + math.pi * (i / 180)
        x = cx + math.cos(angle) * arch_radius
        y = door_top + arch_radius + math.sin(angle) * arch_radius
        door_points.append((x, y))
    door_points.append((door_left + door_w, body_bottom))
    door_points.append((door_left, body_bottom))
    draw.polygon(door_points, fill=TEAL)


def make_master(size: int = 1024, *, with_background: bool = True, padding_ratio: float = 0.0) -> Image.Image:
    """둥근 방패+집 아이콘 master.

    배경: 둥근 사각 (Android squircle 대비).
    중앙: 둥근 방패 흰색 + 짙은 teal stroke + 그 안에 둥근 집.
    """
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    if with_background:
        r = int(size * 0.24)
        # 그라데이션 느낌을 위해 두 단계로 깔기
        draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=TEAL)
        # 하단부에 살짝 밝은 띠로 입체감
        highlight_top = int(size * 0.62)
        draw.rounded_rectangle(
            [0, highlight_top, size - 1, size - 1],
            radius=r,
            fill=(13, 102, 95, 200),
        )
        # 가장자리 부드러운 빛
        glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        glow_draw = ImageDraw.Draw(glow)
        glow_draw.rounded_rectangle(
            [int(size * 0.08), int(size * 0.05), int(size * 0.92), int(size * 0.45)],
            radius=int(size * 0.28),
            fill=(TEAL_LIGHT[0], TEAL_LIGHT[1], TEAL_LIGHT[2], 90),
        )
        glow = glow.filter(ImageFilter.GaussianBlur(radius=int(size * 0.04)))
        img.alpha_composite(glow)
        draw = ImageDraw.Draw(img)

    safe = 1 - padding_ratio
    cx = size / 2
    cy = size / 2
    shield_w = size * 0.64 * safe
    shield_h = size * 0.74 * safe

    # 그림자: 살짝 떨어뜨려 부드러운 입체감
    if with_background:
        shadow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        shadow_draw = ImageDraw.Draw(shadow)
        shadow_pts = shield_path(cx, cy + size * 0.012, shield_w * 1.02, shield_h * 1.02)
        shadow_draw.polygon(shadow_pts, fill=(0, 40, 36, 110))
        shadow = shadow.filter(ImageFilter.GaussianBlur(radius=int(size * 0.018)))
        img.alpha_composite(shadow)
        draw = ImageDraw.Draw(img)

    stroke = max(4, int(size * 0.022))
    draw_shield(draw, cx, cy, shield_w, shield_h, fill=WHITE, outline=TEAL_DARK, width=stroke)

    # 집은 방패 가운데. 시선이 위쪽으로 살짝 모이게 약간 위로.
    house_w = shield_w * 0.58
    house_h = shield_h * 0.5
    house_cy = cy - shield_h * 0.04
    draw_house(draw, cx, house_cy, house_w, house_h, fill=TEAL)

    return img


def make_foreground(size: int = 1024) -> Image.Image:
    """Adaptive icon foreground. 배경 투명 + 중앙 안전 영역(66%)에만 그래픽."""
    return make_master(size=size, with_background=False, padding_ratio=0.17)


def save_webp(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="WEBP", quality=92, method=6)


def save_png(img: Image.Image, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, format="PNG", optimize=True)


def main() -> None:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/4] master 1024 (둥근 사각 배경 + 둥근 방패 + 둥근 집)")
    master = make_master(1024)
    save_png(master, ASSETS_DIR / "icon.png")
    print(f"      -> {ASSETS_DIR / 'icon.png'}")

    print("[2/4] adaptive foreground 1024 (배경 투명, 안전 영역 66%)")
    foreground = make_foreground(1024)
    save_png(foreground, ASSETS_DIR / "adaptive-icon-foreground.png")

    print("[3/4] Android mipmap webp 5종 (legacy + round, 정사각 마스크는 Android 가 자동 처리)")
    for name, px in DENSITIES.items():
        density_dir = ANDROID_RES / f"mipmap-{name}"
        resized = master.resize((px, px), Image.LANCZOS)
        save_webp(resized, density_dir / "ic_launcher.webp")
        save_webp(resized, density_dir / "ic_launcher_round.webp")
        print(f"      mipmap-{name}: {px}px")

    print("[4/4] 완료")


if __name__ == "__main__":
    main()
