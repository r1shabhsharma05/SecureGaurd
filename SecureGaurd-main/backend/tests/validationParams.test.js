'use strict';

// Day 11 — strict id params (SEC-18 / SEC-22 completion).
// Route handlers used parseInt(req.params.id) + isNaN, which silently
// coerces "12abc" -> 12 and "12.5" -> 12 (Number() gave 12.5): a
// malformed id resolved to a real record instead of a 400. parseIdParam
// (utils/validation.js) accepts only a digits-only safe positive
// integer. These tests pin that behaviour with literals. Pure unit
// tests: no DB, no network, no secrets. Run:
//   node --test backend/tests/validationParams.test.js
// from SecureGaurd-main.

const test = require('node:test');
const assert = require('node:assert/strict');

const { parseIdParam } = require('../utils/validation');

test('parseIdParam accepts clean positive integer strings', () => {
  assert.equal(parseIdParam('1'), 1);
  assert.equal(parseIdParam('42'), 42);
  assert.equal(parseIdParam('007'), 7);
  assert.equal(parseIdParam('9007199254740991'), 9007199254740991);
});

test('parseIdParam rejects the coercions parseInt/Number allowed', () => {
  assert.equal(parseIdParam('12abc'), null);
  assert.equal(parseIdParam('12.5'), null);
  assert.equal(parseIdParam('12.0'), null);
  assert.equal(parseIdParam('-3'), null);
  assert.equal(parseIdParam('+12'), null);
  assert.equal(parseIdParam(' 12'), null);
  assert.equal(parseIdParam('12 '), null);
  assert.equal(parseIdParam('1e3'), null);
  assert.equal(parseIdParam('0x10'), null);
});

test('parseIdParam rejects zero, empty and non-string input', () => {
  assert.equal(parseIdParam('0'), null);
  assert.equal(parseIdParam(''), null);
  assert.equal(parseIdParam(undefined), null);
  assert.equal(parseIdParam(null), null);
  assert.equal(parseIdParam(12), null);
  assert.equal(parseIdParam(['12']), null);
});

test('parseIdParam rejects digit strings beyond the safe-integer range', () => {
  assert.equal(parseIdParam('9007199254740993'), null);
  assert.equal(parseIdParam('99999999999999999999999'), null);
});
