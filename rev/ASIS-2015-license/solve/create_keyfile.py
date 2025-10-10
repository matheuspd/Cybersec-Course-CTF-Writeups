from pwn import *

answer = "iKWoZLVc4LTyGrCRedPhfEnihgyGxWrCGjvi37pnPGh2f1DJKEcQZMDlVvZpEHHzU"
answer = answer.encode()
a4 = answer[24:30]
a2 = xor(xor(a4, chr(0x23)*6), answer[6:12])
a1 = xor(answer[0:6], a2)
a3 = xor(answer[12:18], a4)
a5 = xor(xor(xor(answer[18:24], a3), a4), chr(0x23)*6)

# Convert to strings and write in text mode
with open("MATIAS!", "w") as f:
    lines = [a1.decode() + "\n", a2.decode() + "\n", a3.decode() + "\n", a4.decode() + "\n", a5.decode()]
    f.writelines(lines)
