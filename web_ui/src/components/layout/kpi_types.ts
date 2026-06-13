export type KpiBreakdownSegment = { label: string; value: number; color: string };

export type KpiItem = {
  label: string;
  value: string;
  tone?: string;
  icon?: string;
  note?: string;
  breakdown?: KpiBreakdownSegment[];
};
