import { describe, it, expect } from 'vitest'
import { chunk } from '../src/upstream.js'

// The blind relay slices the enclave's ciphertext into N ordered SSE chunks (one MPP
// voucher tick each). Whatever the count, reassembly MUST be lossless — the agent
// concatenates the frames back into the exact ciphertext before decrypting.
describe('chunk', () => {
  it('returns a single chunk for n <= 1', () => {
    expect(chunk('hello world', 1)).toEqual(['hello world'])
    expect(chunk('hello world', 0)).toEqual(['hello world'])
  })

  it('splits into n ordered chunks that reassemble losslessly', () => {
    const s = 'abcdefghij'
    for (const n of [2, 3, 4, 5]) {
      const parts = chunk(s, n)
      expect(parts.length).toBeGreaterThan(1)
      expect(parts.join('')).toBe(s)
    }
  })

  it('does not over-split a string shorter than n', () => {
    expect(chunk('ab', 5)).toEqual(['ab'])
  })
})
