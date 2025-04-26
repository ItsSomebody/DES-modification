import sys
import random

def B2D(binary_str):
    return int(binary_str, 2)

def D2B(n, length):
    return format(n, f'0{length}b')

def binary_to_hex(binary_str):
    if len(binary_str) % 4 != 0:
        binary_str = binary_str.zfill((len(binary_str) + 3) // 4 * 4)
    decimal = int(binary_str, 2)
    return format(decimal, f'0{len(binary_str)//4}x').upper()

def randomIP():
    ip = list(range(1, 65))
    random.shuffle(ip)
    return ip

def inverseRandomIP(ip):
    fp = [0] * 64
    for i, pos in enumerate(ip):
        fp[pos - 1] = i + 1
    return fp

IP = randomIP()
FP = inverseRandomIP(IP)

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

def expandBits(input_bits):
    if len(input_bits) != 32:
        input_bits = input_bits.ljust(32, '0')[:32]
    E = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    output = ''.join(input_bits[i-1] for i in E)
    return output[:48]

def permute(input_bits, table, output_length):
    result = ''.join(input_bits[i - 1] for i in table if i - 1 < len(input_bits))
    return result.ljust(output_length, '0')

def circLeftShift(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]

def countRuns(bits):
    if not bits:
        return 0
    runs = 1
    current_bit = bits[0]
    for bit in bits[1:]:
        if bit != current_bit:
            runs += 1
            current_bit = bit
    return runs

def leftHalfAlgorithm(left):
    groups = [left[i:i+4] for i in range(0, 28, 4)]
    for i in range(2, 6):
        val_i = B2D(groups[i])
        val_prev = B2D(groups[i-1])
        result = (val_i * val_prev) % 16
        groups[i-1] = D2B(result, 4)
    groups[6] = groups[6][::-1]
    modified_left = ''.join(groups)
    return modified_left

def subkeyGen(key):
    try:
        key_permuted = permute(key, PC1, 56)
        left, right = key_permuted[:28], key_permuted[28:]
        num_runs = countRuns(left)
        right = circLeftShift(right, num_runs)
        left = leftHalfAlgorithm(left)
        subkeys = []
        for _ in range(16):
            combined = left + right
            subkey = permute(combined, PC2, 48)
            subkeys.append(subkey)
            right = circLeftShift(right, num_runs)
        return subkeys
    except BrokenPipeError:
        sys.stdout.close()
        raise
    except Exception as e:
        print(f"Error in subkey generation: {str(e)}", file=sys.stderr)
        raise

def sboxLoockup(bits, sbox):
    row = B2D(bits[0] + bits[5])
    col = B2D(bits[1:5])
    output = sbox[row][col]
    return D2B(output, 4)

def roundFunc(right, subkey, sboxes):
    try:
        right = right.ljust(32, '0')[:32]
        expanded = expandBits(right)
        xored = D2B(B2D(expanded) ^ B2D(subkey), 48)
        output = ''
        for i in range(8):
            block = xored[i*6:(i+1)*6]
            if len(block) != 6:
                block = block.ljust(6, '0')
            sbox_output = sboxLoockup(block, sboxes[i])
            output += sbox_output
        output = permute(output, P, 32)
        return output
    except BrokenPipeError:
        sys.stdout.close()
        raise

def encryption(plaintext, key):
    try:
        if len(plaintext) != 64 or len(key) != 64:
            raise ValueError("Plaintext and key must be 64-bit binary strings")
        if not all(bit in '01' for bit in plaintext + key):
            raise ValueError("Plaintext and key must contain only 0s and 1s")
        text = permute(plaintext, IP, 64)
        subkeys = subkeyGen(key)
        left, right = text[:32], text[32:]
        for i in range(16):
            temp = right
            f_output = roundFunc(right, subkeys[i], SBOXES)
            f_output = f_output.ljust(32, '0')[:32]
            left_int = B2D(left)
            f_int = B2D(f_output)
            right = D2B(left_int ^ f_int, 32)
            left = temp
        combined = right + left
        ciphertext = permute(combined, FP, 64)
        return ciphertext
    except BrokenPipeError:
        sys.stdout.close()
        raise
    except Exception as e:
        print(f"Error in encryption: {str(e)}", file=sys.stderr)
        raise

def decryption(ciphertext, key):
    try:
        if len(ciphertext) != 64 or len(key) != 64:
            raise ValueError("Ciphertext and key must be 64-bit binary strings")
        if not all(bit in '01' for bit in ciphertext + key):
            raise ValueError("Plaintext and key must contain only 0s and 1s")
        text = permute(ciphertext, IP, 64)
        subkeys = subkeyGen(key)
        left, right = text[:32], text[32:]
        for i in range(15, -1, -1):
            temp = right
            f_output = roundFunc(right, subkeys[i], SBOXES)
            f_output = f_output.ljust(32, '0')[:32]
            left_int = B2D(left)
            f_int = B2D(f_output)
            right = D2B(left_int ^ f_int, 32)
            left = temp
        combined = right + left
        plaintext = permute(combined, FP, 64)
        return plaintext
    except BrokenPipeError:
        sys.stdout.close()
        raise
    except Exception as e:
        print(f"Error in decryption: {str(e)}", file=sys.stderr)
        raise

def test_permutation():
    """Test if IP followed by IP^-1 restores the original input."""
    test_input = "0000000100100011010001010110011110001001101010111100110111101111"
    permuted = permute(test_input, IP, 64)
    restored = permute(permuted, FP, 64)
    print("\nTesting IP and IP^-1:")
    print(f"Original input: {test_input}")
    print(f"After IP:       {permuted}")
    print(f"After IP^-1:    {restored}")
    print(f"IP and IP^-1 correct: {restored == test_input}")

def test_expansion():
    """Test the bit expansion function."""
    test_input = "10110010101100111100110111101111"
    expanded = expandBits(test_input)
    print("\nTesting Bit Expansion (32 to 48 bits):")
    print(f"Input (32 bits):  {test_input}")
    print(f"Output (48 bits): {expanded}")
    print(f"Output length:    {len(expanded)}")
    print(f"Valid output:     {len(expanded) == 48 and all(bit in '01' for bit in expanded)}")

def test_subkey_generation():
    """Test the subkey generation process with multiple test cases."""
    test_cases = [
        {
            "key": "0010110001111101101001110111010001101000110001000100001101001101",
            "description": "Standard test key from original code"
        },
        {
            "key": "0000000000000000000000000000000000000000000000000000000000000000",
            "description": "All zeros key (edge case, 1 run)"
        },
        {
            "key": "1111111111111111111111111111111111111111111111111111111111111111",
            "description": "All ones key (edge case, 1 run)"
        },
        {
            "key": "0101010101010101010101010101010101010101010101010101010101010101",
            "description": "Alternating bits key (max runs)"
        }
    ]
    
    for test_case in test_cases:
        key = test_case["key"]
        description = test_case["description"]
        print(f"\nTesting Subkey Generation: {description}")
        print(f"Input Key (64 bits): {key}")
        
        try:
            subkeys = subkeyGen(key)
            key_permuted = permute(key, PC1, 56)
            left_half = key_permuted[:28]
            right_half_original = key_permuted[28:]
            num_runs = countRuns(left_half)
            expected_right_half = circLeftShift(right_half_original, num_runs)
            modified_left = leftHalfAlgorithm(left_half)
            left_groups = [left_half[i:i+4] for i in range(0, 28, 4)]
            expected_groups = [modified_left[i:i+4] for i in range(0, 28, 4)]
            
            if len(key) != 64 or not all(bit in '01' for bit in key):
                print("Test 1 FAILED: Key must be 64 bits and contain only 0s and 1s")
                continue
            print("Test 1 PASSED: Key is 64 bits and valid")
            
            if len(key_permuted) != 56 or not all(bit in '01' for bit in key_permuted):
                print("Test 2 FAILED: PC-1 output must be 56 bits and valid")
                continue
            print("Test 2 PASSED: PC-1 permutation produced 56-bit key")
            
            if len(left_half) != 28 or len(right_half_original) != 28:
                print("Test 3 FAILED: Left and right halves must be 28 bits each")
                continue
            print(f"Test 3 PASSED: Key split into 28-bit halves")
            print(f"Left Half (before modification): {left_half}")
            print(f"Right Half (before run-based shift): {right_half_original}")
            
            computed_runs = countRuns(left_half)
            if num_runs != computed_runs:
                print(f"Test 4 FAILED: Number of runs incorrect (got {num_runs}, expected {computed_runs})")
                continue
            print(f"Test 4 PASSED: Number of runs in left half: {num_runs}")
            
            first_subkey = subkeys[0]
            combined = modified_left + expected_right_half
            expected_first_subkey = permute(combined, PC2, 48)
            if first_subkey != expected_first_subkey:
                print("Test 5 FAILED: Right half shift or left half modification incorrect")
                continue
            print(f"Test 5 PASSED: Right half shifted by {num_runs} bits")
            
            for i in range(2, 6):
                val_i = B2D(left_groups[i])
                val_prev = B2D(left_groups[i-1])
                expected = (val_i * val_prev) % 16
                if expected_groups[i-1] != D2B(expected, 4):
                    print(f"Test 6 FAILED: Group {i-1} modification incorrect")
                    break
            else:
                if expected_groups[6] != left_groups[6][::-1]:
                    print("Test 6 FAILED: Group 7 reversal incorrect")
                else:
                    print(f"Test 6 PASSED: Left half modified correctly")
                    print(f"Left Half (after modification): {modified_left}")
            
            if len(subkeys) != 16:
                print(f"Test 7 FAILED: Expected 16 subkeys, got {len(subkeys)}")
                continue
            print("Test 7 PASSED: Generated 16 subkeys")
            
            for i, subkey in enumerate(subkeys):
                if len(subkey) != 48 or not all(bit in '01' for bit in subkey):
                    print(f"Test 8 FAILED: Subkey {i+1} is not 48 bits or contains invalid bits")
                    break
            else:
                print("Test 8 PASSED: All subkeys are 48 bits and valid")
            
            current_right = expected_right_half
            for i in range(1, 16):
                current_right = circLeftShift(current_right, num_runs)
                combined = modified_left + current_right
                expected_subkey = permute(combined, PC2, 48)
                if subkeys[i] != expected_subkey:
                    print(f"Test 9 FAILED: Subkey {i+1} does not match expected shift by {num_runs}")
                    break
            else:
                print(f"Test 9 PASSED: All right half shifts use {num_runs} positions")
            
            print("\nFirst 3 Subkeys:")
            for i in range(min(3, len(subkeys))):
                print(f"Subkey {i+1}: {subkeys[i]}")
            
            print(f"\nAll tests PASSED for {description}!")
            
        except Exception as e:
            print(f"Test FAILED for {description}: An error occurred: {str(e)}")

def test_des():
    key = "0010110001111101101001110111010001101000110001000100001101001101"
    test_cases = [
        {
            "plaintext": "0000000100100011010001010110011110001001101010111100110111101111",
            "description": "Original test plaintext"
        },
        {
            "plaintext": ''.join(random.choice('01') for _ in range(64)),
            "description": "Random plaintext"
        }
    ]

    print("\nTesting DES encryption and decryption with multiple plaintexts...")
    print(f"Key (hex): {binary_to_hex(key)}")
    print(f"Key (binary): {key}\n")

    for idx, test_case in enumerate(test_cases, 1):
        plaintext = test_case["plaintext"]
        description = test_case["description"]
        print(f"Test Case {idx}: {description}")
        print(f"Plaintext (hex): {binary_to_hex(plaintext)}")
        print(f"Plaintext (binary): {plaintext}")
        
        try:
            ciphertext = encryption(plaintext, key)
            print(f"Ciphertext (hex): {binary_to_hex(ciphertext)}")
            print(f"Ciphertext (binary): {ciphertext}")
            
            decrypted = decryption(ciphertext, key)
            print(f"Decrypted (hex): {binary_to_hex(decrypted)}")
            print(f"Decrypted (binary): {decrypted}")
            print(f"Matches original: {decrypted == plaintext}\n")
        except Exception as e:
            print(f"An error occurred in Test Case {idx}: {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    #test_permutation()
    #test_expansion()
    #test_subkey_generation()
    test_des()