export const DEFAULT_STACKED_CARD_EFFECTIVE_WIDTH = 520;

/**
 * 화면 폭뿐 아니라 사용자가 키운 글자 배율까지 고려해, 한 행의 고정 요소가
 * 본문 폭을 빼앗기 전에 카드 내용을 세로로 쌓는다.
 */
export function shouldUseStackedCardLayout(
  width: number,
  fontScale: number,
  minimumEffectiveWidth = DEFAULT_STACKED_CARD_EFFECTIVE_WIDTH,
): boolean {
  const safeThreshold =
    Number.isFinite(minimumEffectiveWidth) && minimumEffectiveWidth > 0
      ? minimumEffectiveWidth
      : DEFAULT_STACKED_CARD_EFFECTIVE_WIDTH;
  const safeWidth = Number.isFinite(width) && width > 0 ? width : safeThreshold;
  const safeFontScale = Number.isFinite(fontScale) && fontScale > 1 ? fontScale : 1;
  return safeWidth / safeFontScale < safeThreshold;
}
