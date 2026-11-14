/**
 * Compatibility boundary only. The active design system is Studio Halo;
 * legacy imports are aliases so older integrations do not silently change
 * behavior while the old visual implementation remains retired.
 */
export {
  StudioCommand as PremiumAction,
  StudioHero as PremiumHero,
  StudioSection as PremiumSection,
  StudioSignalRibbon as PremiumMetricGrid,
  StudioStatus as PremiumStatus,
  StudioStageRail as AtelierStageRail,
} from "./StudioPrimitives";
export type { StudioMetric as PremiumMetric, StudioStage as AtelierStage } from "./StudioPrimitives";
