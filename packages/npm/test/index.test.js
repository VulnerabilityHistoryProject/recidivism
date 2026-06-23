import test from "node:test";
import assert from "node:assert/strict";

import { parse_recidivism } from "../src/recidivism.js";

test("parse_recidivism returns undefined for undefined input", () => {
  assert.equal(parse_recidivism(undefined), null);
});

test("parse_recidivism returns undefined for null input", () => {
  assert.equal(parse_recidivism(null), null);
});

test("parse_recidivism correctly parses a valid recidivism string", () => {
  const recidivism_string = "1.0:High";
  const expected_output = {	version: "1.0", severity: "High"};
  assert.deepEqual(parse_recidivism(recidivism_string), expected_output);
});
