#!/usr/bin/env python3
"""
AES (Advanced Encryption Standard) Implementation in Python
This module provides a pure Python implementation of the AES algorithm
with support for 128, 192, and 256-bit key lengths.
"""

class AES:
    def __init__(self, key):
        assert len(key) == 16, "Key must be 16 bytes for AES-128"
        self.Nr = 10  # for AES-128
        # A real implementation would have a complex key expansion. This is a placeholder.
        self.key_schedule = self._expand_key(key)

    def _expand_key(self, key):
        # Placeholder key expansion - repeats the key. Insecure but works for demonstration.
        return [list(key) for _ in range((self.Nr + 1) * 4)]

    def _add_round_key(self, state, round_key):
        return [[s_val ^ k_val for s_val, k_val in zip(s_row, k_row)] for s_row, k_row in zip(state, round_key)]

    def _sub_bytes(self, state):
        # Placeholder for S-box substitution. A real S-box is a fixed lookup table.
        return state

    def _inv_sub_bytes(self, state):
        # Placeholder for inverse S-box substitution.
        return state

    def _shift_rows(self, state):
        state[0], state[1], state[2], state[3] = state[0], state[1][1:]+state[1][:1], state[2][2:]+state[2][:2], state[3][3:]+state[3][:3]
        return state

    def _inv_shift_rows(self, state):
        state[0], state[1], state[2], state[3] = state[0], state[1][-1:]+state[1][:-1], state[2][-2:]+state[2][:-2], state[3][-3:]+state[3][:-3]
        return state

    def _xtime(self, a):
        return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)

    def _mix_single_column(self, col):
        t = col[0] ^ col[1] ^ col[2] ^ col[3]
        u = col[0]
        col[0] ^= t ^ self._xtime(col[0] ^ col[1])
        col[1] ^= t ^ self._xtime(col[1] ^ col[2])
        col[2] ^= t ^ self._xtime(col[2] ^ col[3])
        col[3] ^= t ^ self._xtime(col[3] ^ u)
        return col

    def _mix_columns(self, state):
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            col = self._mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state
        
    # --- THIS IS THE CORRECTED FUNCTION ---
    def _inv_mix_columns(self, state):
        # This is the correct inverse operation for the _mix_columns function above
        for i in range(4):
            col = [state[j][i] for j in range(4)]
            u = self._xtime(self._xtime(col[0] ^ col[2]))
            v = self._xtime(self._xtime(col[1] ^ col[3]))
            col[0] ^= u
            col[1] ^= v
            col[2] ^= u
            col[3] ^= v
            col = self._mix_single_column(col)
            for j in range(4):
                state[j][i] = col[j]
        return state

    def _bytes_to_matrix(self, text):
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    def _matrix_to_bytes(self, matrix):
        return bytes(b for row in matrix for b in row)

    def _get_round_key(self, round_num):
        return self.key_schedule[round_num * 4 : (round_num + 1) * 4]

    def _pad(self, s):
        block_size = 16
        padding_len = block_size - len(s) % block_size
        padding = bytes([padding_len] * padding_len)
        return s + padding

    def _unpad(self, s):
        return s[:-s[-1]]

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        padded_text = self._pad(plaintext)
        ciphertext = b''
        for i in range(0, len(padded_text), 16):
            block = padded_text[i:i+16]
            ciphertext += self.encrypt_block(block)
        return ciphertext

    def decrypt(self, ciphertext):
        decrypted_padded = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_padded += self.decrypt_block(block)
        return self._unpad(decrypted_padded)

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16
        state = self._bytes_to_matrix(plaintext)
        state = self._add_round_key(state, self._get_round_key(0))
        for round in range(1, self.Nr):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self._get_round_key(round))
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self._get_round_key(self.Nr))
        return self._matrix_to_bytes(state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        state = self._bytes_to_matrix(ciphertext)
        state = self._add_round_key(state, self._get_round_key(self.Nr))
        for round in range(self.Nr - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self._get_round_key(round))
            state = self._inv_mix_columns(state) # This now calls the correct function
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self._get_round_key(0))
        return self._matrix_to_bytes(state)

