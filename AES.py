# ============================================================ 
        ## Group assignment 

# 1. Bemiheret Tabushe  088

# 2. Eyob Tesfa         053

# ============================================================ 


# ============================================================ 
# AES-128 IMPLEMENTATION (FULL FILE WITH ROUND TRACING)
# ============================================================ 

# ---------------- TABLES (THE "CODE BOOKS") ----------------- 

# The S_BOX (Substitution Box) is a non-linear lookup table.
# Every input byte is replaced by the value at its corresponding coordinates.
# This creates 'Confusion', ensuring there is no simple linear relationship between 
# the plaintext and the ciphertext.
S_BOX = [ 
  [99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118], 
  [202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192], 
  [183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21], 
  [4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117], 
  [9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132], 
  [83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207], 
  [208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168], 
  [81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210], 
  [205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115], 
  [96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219], 
  [224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121], 
  [231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8], 
  [186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138], 
  [112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158], 
  [225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223], 
  [140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22] 
] 

# The INV_S_BOX is the inverse lookup table.
# It is used during decryption to map a substituted byte back to its original value.
INV_S_BOX = [[0]*16 for _ in range(16)] 
for i in range(16): 
    for j in range(16): 
        val = S_BOX[i][j] 
        INV_S_BOX[val >> 4][val & 0x0F] = i*16 + j 

# RCON (Round Constants) are used in the Key Expansion process.
# They are XORed into the first byte of a word to break symmetry and ensure 
# that each round's key is significantly different.
RCON = [[1,0,0,0], [2,0,0,0], [4,0,0,0], [8,0,0,0], [16,0,0,0], 
        [32,0,0,0], [64,0,0,0], [128,0,0,0], [27,0,0,0], [54,0,0,0]] 

# ----------------- BASIC TOOLS -------------------------- 

def xor_words(a, b): 
    """Combines two 4-byte lists using the bitwise XOR operator."""
    return [x ^ y for x, y in zip(a, b)] 

def rot_word(word): 
    """Cyclically shifts a 4-byte word: [b0, b1, b2, b3] becomes [b1, b2, b3, b0]."""
    return word[1:] + word[:1] 

def sub_word(word): 
    """Applies the S_BOX substitution to each byte in a 4-byte word."""
    return [S_BOX[b >> 4][b & 0x0F] for b in word] 

def gmul(a, b): 
    """
    Multiplies two numbers in the Galois Field (GF(2^8)). 
    This ensures the result remains within the range of a single byte (0-255) 
    without overflowing.
    """
    p = 0 
    for _ in range(8): 
        if b & 1: p ^= a 
        hi = a & 0x80 
        a = (a << 1) & 0xFF 
        if hi: a ^= 0x1B # Irreducible polynomial used in AES
        b >>= 1 
    return p 

# ---------------- PRINTING HELPERS ------------------------ 

def print_matrix(label, state, round_idx):
    """Formats the internal 4x4 state grid into a readable hex table for debugging."""
    print(f"\n[{label} - Round {round_idx}]")
    for r in range(4):
        row = [f"{state[r][c]:02x}" for c in range(4)]
        print("  ".join(row))

def print_key_matrix(label, words, round_idx):
    """Formats the 4-word round key as a 4x4 matrix to match the state display."""
    print(f"\n[{label} - Round {round_idx}]")
    for r in range(4):
        row = [f"{words[c][r]:02x}" for c in range(4)]
        print("  ".join(row))

# ---------------- KEY GENERATOR ----------------------------- 

def key_expansion(key): 
    """
    Takes the initial 16-byte user key and 'expands' it into 11 separate 
    round keys (44 words total). This ensures each round of AES uses a unique key.
    """
    key_bytes = [ord(c) for c in key.ljust(16)[:16]] 
    w = [key_bytes[i:i+4] for i in range(0, 16, 4)] # Initial 4 words from user key
    for i in range(4, 44): 
        temp = w[i-1] 
        if i % 4 == 0: 
            # Apply transformation to every 4th word: Rotate, Substitute, then XOR with RCON
            temp = sub_word(rot_word(temp))
            temp = xor_words(temp, RCON[(i//4) - 1]) 
        w.append(xor_words(w[i-4], temp)) 
    return w

# ---------------- CORE SCRAMBLING STEPS --------------------- 

def add_round_key(state, round_key_words): 
    """
    XORs the current 4x4 state matrix with the current round's subkey. 
    This is the only step that actually uses the secret key.
    """
    for c in range(4): 
        for r in range(4): 
            state[r][c] ^= round_key_words[c][r] 

def sub_bytes(state): 
    """Applies S_BOX substitution to every byte in the 4x4 state grid."""
    for i in range(4): 
        for j in range(4): 
            b = state[i][j] 
            state[i][j] = S_BOX[b >> 4][b & 0x0F] 

def inv_sub_bytes(state): 
    """Undoes the sub_bytes step using the INV_S_BOX."""
    for i in range(4): 
        for j in range(4): 
            b = state[i][j] 
            state[i][j] = INV_S_BOX[b >> 4][b & 0x0F] 

def shift_rows(state): 
    """
    Provides 'Diffusion' by shifting rows:
    Row 0: No shift
    Row 1: Shift left by 1 byte
    Row 2: Shift left by 2 bytes
    Row 3: Shift left by 3 bytes
    """
    state[1] = state[1][1:] + state[1][:1] 
    state[2] = state[2][2:] + state[2][:2] 
    state[3] = state[3][3:] + state[3][:3] 

def inv_shift_rows(state): 
    """Undoes shift_rows by shifting the rows back to the right."""
    state[1] = state[1][-1:] + state[1][:-1] 
    state[2] = state[2][-2:] + state[2][:-2] 
    state[3] = state[3][-3:] + state[3][:-3] 

def mix_columns(state): 
    """
    Mixes the data within each column using matrix multiplication in GF(2^8).
    This ensures that a change in one byte eventually affects the whole column.
    """
    for c in range(4): 
        col = [state[r][c] for r in range(4)] 
        state[0][c] = gmul(col[0],2)^gmul(col[1],3)^col[2]^col[3] 
        state[1][c] = col[0]^gmul(col[1],2)^gmul(col[2],3)^col[3] 
        state[2][c] = col[0]^col[1]^gmul(col[2],2)^gmul(col[3],3) 
        state[3][c] = gmul(col[0],3)^col[1]^col[2]^gmul(col[3],2) 

def inv_mix_columns(state): 
    """Undoes the mix_columns transformation using inverse multiplication constants."""
    for c in range(4): 
        col = [state[r][c] for r in range(4)] 
        state[0][c] = gmul(col[0],14)^gmul(col[1],11)^gmul(col[2],13)^gmul(col[3],9) 
        state[1][c] = gmul(col[0],9)^gmul(col[1],14)^gmul(col[2],11)^gmul(col[3],13) 
        state[2][c] = gmul(col[0],13)^gmul(col[1],9)^gmul(col[2],14)^gmul(col[3],11) 
        state[3][c] = gmul(col[0],11)^gmul(col[1],13)^gmul(col[2],9)^gmul(col[3],14) 

# ---------------- ENCRYPTION --------------------------- 

def aes_encrypt(plaintext, key): 
    """
    Orchestrates the encryption process: 
    1. Initial Round Key addition.
    2. 9 Rounds of: SubBytes, ShiftRows, MixColumns, AddRoundKey.
    3. Final Round: SubBytes, ShiftRows, AddRoundKey (No MixColumns).
    """
    plaintext = plaintext.ljust(16)[:16]
    # Convert plaintext characters into a 4x4 matrix (State)
    state = [[ord(plaintext[i + 4*j]) for j in range(4)] for i in range(4)] 
    keys = key_expansion(key) 

    # Round 0: Initial Key Addition
    print_key_matrix("KEY MATRIX", keys[0:4], 0)
    add_round_key(state, keys[0:4]) 
    print_matrix("STATE MATRIX", state, 0)

    # Rounds 1-9: The main loop
    for r in range(1, 10): 
        sub_bytes(state) 
        shift_rows(state) 
        mix_columns(state) 
        round_key = keys[4*r : 4*(r+1)]
        add_round_key(state, round_key) 
        print_key_matrix("KEY MATRIX", round_key, r)
        print_matrix("STATE MATRIX", state, r)

    # Final Round (Round 10): Note that MixColumns is skipped here
    sub_bytes(state) 
    shift_rows(state) 
    add_round_key(state, keys[40:44]) 
    print_key_matrix("KEY MATRIX", keys[40:44], 10)
    print_matrix("FINAL STATE", state, 10)

    return state 

# ---------------- DECRYPTION --------------------------- 

def aes_decrypt(state, key): 
    """
    Orchestrates the decryption process by performing the inverse 
    of encryption steps in reverse order.
    """
    keys = key_expansion(key) 

    # Start with the last round key
    print_key_matrix("KEY MATRIX", keys[40:44], 10)
    add_round_key(state, keys[40:44]) 
    print_matrix("STATE MATRIX", state, 10)

    # Reverse Rounds 9 down to 1
    for r in range(9, 0, -1): 
        inv_shift_rows(state) 
        inv_sub_bytes(state) 
        round_key = keys[4*r : 4*(r+1)]
        add_round_key(state, round_key) 
        inv_mix_columns(state) 
        print_key_matrix("KEY MATRIX", round_key, r)
        print_matrix("STATE MATRIX", state, r)

    # Final reversal (Round 0)
    inv_shift_rows(state) 
    inv_sub_bytes(state) 
    add_round_key(state, keys[0:4]) 
    print_key_matrix("KEY MATRIX", keys[0:4], 0)
    print_matrix("FINAL RECOVERED STATE", state, 0)

    return state

# ---------------- INTERACTIVE MENU --------------------------- 

def main():
    """Handles user input, menu logic, and hex formatting for output."""
    while True:
        print("\n" + "="*40)
        print("         AES-128 BEGINNER TOOL")
        print("="*40)
        print("1. Encrypt Plaintext")
        print("2. Decrypt Hex Ciphertext")
        print("3. Exit")
        choice = input("Your choice (1-3): ")

        if choice == '1':
            pt = input("Enter Plaintext: ")
            k = input("Enter Secret Key: ")
            cipher_state = aes_encrypt(pt, k)
            # Convert the final 4x4 state matrix into a single hex string
            hex_output = ''.join(f"{cipher_state[r][c]:02x}" for c in range(4) for r in range(4))
            print(f"\nFINAL ENCRYPTED HEX: {hex_output}")

        elif choice == '2':
            hex_str = input("Paste Hex Ciphertext: ")
            k = input("Enter Secret Key: ")
            try:
                # Convert the user's hex string back into bytes
                data_bytes = bytes.fromhex(hex_str)
                # Arrange those bytes into a 4x4 matrix for processing
                state = [[0]*4 for _ in range(4)]
                for i in range(16):
                    state[i % 4][i // 4] = data_bytes[i]
                
                final_state = aes_decrypt(state, k)
                # Convert matrix back to characters
                recovered = ''.join(chr(final_state[r][c]) for c in range(4) for r in range(4))
                print(f"\nRECOVERED MESSAGE: {recovered.strip()}")
            except:
                print("Error: Make sure the Hex string is valid.")

        elif choice == '3':
            print("Closing Tool...")
            break

if __name__ == "__main__":
    main()