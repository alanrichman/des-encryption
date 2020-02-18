def end():
    input("Press enter to quit\n")
    exit()

def str_bin(block):
    return "".join(format(ord(c), "08b") for c in block)

def bin_str(block):
    return "".join(chr(int(block[n:n+8], 2)) for n in range(0, len(block), 8))

def chunkstring(block, length):
    return list(block[0 + i:length + i] for i in range(0, len(block), length))

def str_xor(a, b):
    xor = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            xor += "0"
        else:
            xor += "1"

    return xor

def IP(block):
    if len(block) != 64:
        print("IP block length must be 64")
        end()
        
    ip_arr = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, \
              62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, \
              57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, \
              61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    
    ip_str = ""
    for i in ip_arr:
        if block[i - 1] in ["0", "1"]:
            ip_str += block[i - 1]
        else:
            print("IP expects binary strings only")
            end()

    return ip_str

def FP(block):
    if len(block) != 64:
        print("FP block length must be 64")
        end()
        
    fp_arr = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, \
              38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, \
              36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, \
              34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    
    fp_str = ""
    for i in fp_arr:
        if block[i - 1] in ["0", "1"]:
            fp_str += block[i - 1]
        else:
            print("FP expects binary strings only")
            end()

    return fp_str

def E(block):
    if len(block) != 32:
        print("E block length must be 32")
        end()

    e_arr = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, \
             8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, \
             16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, \
             24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    e_str = ""
    for i in e_arr:
        if block[i - 1] in ["0", "1"]:
            e_str += block[i - 1]
        else:
            print("E expects binary strings only")
            end()

    return e_str

def P(block):
    if len(block) != 32:
        print("P block length must be 32")
        end()

    p_arr = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, \
             2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    p_str = ""
    for i in p_arr:
        if block[i - 1] in ["0", "1"]:
            p_str += block[i - 1]
        else:
            print("P expects binary strings only")
            end()

    return p_str

def PC1(block):
    if len(block) != 64:
        print("PC-1 block length must be 64")
        end()
        
    c_arr = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, \
             10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
    
    c_str = ""
    for i in c_arr:
        if block[i - 1] in ["0", "1"]:
            c_str += block[i - 1]
        else:
            print("PC-1 expects binary strings only")
            end()

    d_arr = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, \
             14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    
    d_str = ""
    for i in d_arr:
        if block[i - 1] in ["0", "1"]:
            d_str += block[i - 1]
        else:
            print("PC-1 expects binary strings only")
            end()

    return [c_str, d_str]

def LS(block, n):
    if len(block) != 28:
        print("LS block length must be 28")
        end()

    ls_str = ""
    for i in range(n, 28):
        if block[i] in ["0", "1"]:
            ls_str += block[i]
        else:
            print("LS expects binary strings only")
            end()
            
    for i in range(n):
        if block[i] in ["0", "1"]:
            ls_str += block[i]
        else:
            print("LS expects binary strings only")
            end()

    return ls_str

def RS(block, n):
    if len(block) != 28:
        print("RS block length must be 28")
        end()

    rs_str = ""
    for i in range(28 - n, 28):
        if block[i] in ["0", "1"]:
            rs_str += block[i]
        else:
            print("RS expects binary strings only")
            end()
            
    for i in range(28 - n):
        if block[i] in ["0", "1"]:
            rs_str += block[i]
        else:
            print("RS expects binary strings only")
            end()

    return rs_str

def PC2(c_block, d_block):
    if len(c_block) != 28 or len(d_block) != 28:
        print("PC-2 block lengths must be 28")
        end()

    block = ""
    for c in c_block:
        if c in ["0", "1"]:
            block += c
        else:
            print("PC-2 expects binary strings only")
            end()
    for d in d_block:
        if d in ["0", "1"]:
            block += d
        else:
            print("PC-2 expects binary strings only")
            end()

    pc2_arr = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, \
               23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, \
               41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, \
               44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    pc2_str = ""
    for i in pc2_arr:
        pc2_str += block[i - 1]

    return pc2_str

def S1(block):
    if len(block) != 6:
        print("S1 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s1_arr = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], \
              [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], \
              [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], \
              [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

    return format(s1_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S2(block):
    if len(block) != 6:
        print("S2 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S2 expects binary strings only")
            end()

    s2_arr = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], \
              [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], \
              [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], \
              [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

    return format(s2_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S3(block):
    if len(block) != 6:
        print("S3 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s3_arr = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], \
              [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], \
              [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], \
              [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

    return format(s3_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S4(block):
    if len(block) != 6:
        print("S4 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s4_arr = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], \
              [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], \
              [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], \
              [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    return format(s4_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S5(block):
    if len(block) != 6:
        print("S5 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s5_arr = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], \
              [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], \
              [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], \
              [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    return format(s5_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S6(block):
    if len(block) != 6:
        print("S6 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s6_arr = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], \
              [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], \
              [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], \
              [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    return format(s6_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S7(block):
    if len(block) != 6:
        print("S7 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s7_arr = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], \
              [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], \
              [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], \
              [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

    return format(s7_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def S8(block):
    if len(block) != 6:
        print("S8 block length must be 6")
        end()

    for c in block:
        if c not in ["0", "1"]:
            print("S1 expects binary strings only")
            end()

    s8_arr = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], \
              [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], \
              [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], \
              [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

    return format(s8_arr[int(block[0] + block[5], 2)][int(block[1:5], 2)], "04b")

def f(block, subkey):
    if len(block) != 32:
        print("f block length must be 32")
        end()
    if len(subkey) != 48:
        print("Subkey length must be 48")
        end()

    e_xor = str_xor(E(block), subkey)

    return P(S1(e_xor[0:6]) + \
             S2(e_xor[6:12]) + \
             S3(e_xor[12:18]) + \
             S4(e_xor[18:24]) + \
             S5(e_xor[24:30]) + \
             S6(e_xor[30:36]) + \
             S7(e_xor[36:42]) + \
             S8(e_xor[42:48]))

# Takes ASCII string
def DES_encrypt(plaintext, key):
    if len(key) != 8:
        print("DES encryption key length must be 8 characters (64 bits)")
        end()
        
    pt_list = chunkstring(plaintext, 8)
    while len(pt_list[len(pt_list) - 1]) != 8:
        pt_list[len(pt_list) - 1] += chr(0) 
    ciphertext = ""
    for pt in pt_list:
        work_text = IP(str_bin(pt))
        work_key = PC1(str_bin(key))
        C = work_key[0]
        D = work_key[1]

        for i in range(16):
            if i + 1 in [1, 2, 9, 16]:
                C = LS(C, 1)
                D = LS(D, 1)
            else:
                C = LS(C, 2)
                D = LS(D, 2)
                
            work_text = work_text[32:64] + str_xor(work_text[0:32], f(work_text[32:64], PC2(C, D)))

        ciphertext += FP(work_text[32:64] + work_text[0:32])

    return ciphertext

# Takes BINARY string
def DES_decrypt(ciphertext, key):
    if len(key) != 8:
        print("DES decryption key length must be 8 characters (64 bits)")
        end()
    
    ct_list = chunkstring(ciphertext, 64)
    plaintext = ""
    for ct in ct_list:
        work_text = IP(ct)
        work_key = PC1(str_bin(key))
        C = work_key[0]
        D = work_key[1]

        for i in range(1, 17): # 1 indexed decryption avoids duplication of next line
            work_text = work_text[32:64] + str_xor(work_text[0:32], f(work_text[32:64], PC2(C, D)))

            if i + 1 in [2, 9, 16]:
                C = RS(C, 1)
                D = RS(D, 1)
            else:
                C = RS(C, 2)
                D = RS(D, 2)

        plaintext += FP(work_text[32:64] + work_text[0:32])
        print(FP(work_text[32:64] + work_text[0:32]))

    return plaintext

while True:
    output = ""
    choice = input("Encrypt (e) or decrypt (d)? (other to quit)\n")
    if choice.lower() == "e":
        output = DES_encrypt(input("input plaintext: "), input("input key: "))
    elif choice.lower() == "d":
        output = bin_str(DES_decrypt(input("input ciphertext: "), input("input key: ")))
    else:
        break

    print(output)


