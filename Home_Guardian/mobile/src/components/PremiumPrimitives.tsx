/** Legacy compatibility exports. New screens must import StudioPrimitives. */
export {
  StudioCommand as PremiumAction,
  StudioHero as PremiumHero,
  StudioSection as PremiumSection,
  StudioSignalRibbon as PremiumMetricGrid,
  StudioStatus as PremiumStatus,
} from "./StudioPrimitives";
export type { StudioMetric as PremiumMetric } from "./StudioPrimitives";
