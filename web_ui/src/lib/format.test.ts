import { describe, expect, it } from "vitest";

import { formatAttackMappings } from "./format";

describe("formatAttackMappings", () => {
  it("formats structured ATT&CK mappings", () => {
    expect(
      formatAttackMappings([
        {
          tactic: "persistence",
          technique_id: "T1543.003",
          technique_name: "Windows Service"
        }
      ])
    ).toBe("T1543.003 Windows Service");
  });

  it("supports legacy strings and incomplete mappings", () => {
    expect(formatAttackMappings(["T1078", { tactic: "execution" }])).toBe(
      "T1078, execution"
    );
    expect(formatAttackMappings([])).toBe("-");
  });
});
