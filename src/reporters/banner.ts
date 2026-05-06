import kleur from "kleur";

export interface BannerProps {
  /** First content row, e.g. "164 packages · 2 affected · 2 findings". */
  metrics: string;
  /** Second content row, typically a scannedAt ISO timestamp. */
  timestamp: string;
}

const BORDER = {
  tl: "┌",
  tr: "┐",
  bl: "└",
  br: "┘",
  h: "─",
  v: "│",
} as const;

const TITLE = "trawly";
const SIDE_PAD = 1; // single space between │ and content
const MIN_TITLE_FILLER = 4; // ensure at least "────" after `─ trawly `

export function renderBanner(props: BannerProps): string {
  const contentRows = [props.metrics, props.timestamp];
  const titleSegment = ` ${TITLE} `; // " trawly "
  const minTitleWidth = 1 + titleSegment.length + MIN_TITLE_FILLER; // ─ + " trawly " + ────

  const innerWidth = Math.max(
    ...contentRows.map((r) => r.length + SIDE_PAD * 2),
    minTitleWidth,
  );

  const top = renderTop(innerWidth);
  const bottom = renderBottom(innerWidth);
  const metricsLine = renderRow(innerWidth, props.metrics, kleur.bold);
  const timestampLine = renderRow(innerWidth, props.timestamp, kleur.gray);

  return [top, metricsLine, timestampLine, bottom].join("\n");
}

function renderTop(innerWidth: number): string {
  const titleSegment = ` ${kleur.bold().cyan(TITLE)} `;
  const titleVisibleLen = TITLE.length + 2; // bold/cyan don't add visible chars
  const fillerCount = innerWidth - 1 - titleVisibleLen; // -1 for the leading "─"
  return (
    kleur.gray(BORDER.tl) +
    kleur.gray(BORDER.h) +
    titleSegment +
    kleur.gray(BORDER.h.repeat(Math.max(MIN_TITLE_FILLER, fillerCount))) +
    kleur.gray(BORDER.tr)
  );
}

function renderBottom(innerWidth: number): string {
  return kleur.gray(`${BORDER.bl}${BORDER.h.repeat(innerWidth)}${BORDER.br}`);
}

function renderRow(
  innerWidth: number,
  content: string,
  colorize: (s: string) => string,
): string {
  const fill = Math.max(0, innerWidth - SIDE_PAD * 2 - content.length);
  return (
    kleur.gray(BORDER.v) +
    " ".repeat(SIDE_PAD) +
    colorize(content) +
    " ".repeat(fill + SIDE_PAD) +
    kleur.gray(BORDER.v)
  );
}
