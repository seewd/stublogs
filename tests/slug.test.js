import test from 'node:test';
import assert from 'node:assert/strict';

import {
  getHostSlug,
  getReservedSlugs,
  slugifyValue,
  validatePostSlug,
  validateSlug,
} from '../src/index.js';

test('validateSlug accepts standard slugs', () => {
  const reserved = getReservedSlugs({ RESERVED_SLUGS: '' });
  const result = validateSlug('alice-01', reserved);
  assert.equal(result.ok, true);
});

test('validateSlug rejects reserved slugs', () => {
  const reserved = getReservedSlugs({ RESERVED_SLUGS: 'test' });
  const result = validateSlug('admin', reserved);
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'slug-reserved');
});

test('validateSlug rejects invalid dash usage', () => {
  const reserved = getReservedSlugs({ RESERVED_SLUGS: '' });
  assert.equal(validateSlug('-bad', reserved).ok, false);
  assert.equal(validateSlug('bad-', reserved).ok, false);
  assert.equal(validateSlug('bad--slug', reserved).ok, false);
});

test('validatePostSlug accepts article slugs', () => {
  const result = validatePostSlug('hello-world-2026');
  assert.equal(result.ok, true);
});

test('getHostSlug extracts first label', () => {
  assert.equal(getHostSlug('alice.bdfz.net', 'bdfz.net'), 'alice');
  assert.equal(getHostSlug('a.b.c.bdfz.net', 'bdfz.net'), 'a');
  assert.equal(getHostSlug('bdfz.net', 'bdfz.net'), null);
});

test('slugifyValue normalizes titles', () => {
  assert.equal(slugifyValue('Hello World!!!'), 'hello-world');
  assert.equal(slugifyValue('  Bear  Style Editor  '), 'bear-style-editor');
});
