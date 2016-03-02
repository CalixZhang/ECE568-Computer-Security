

#Shafaaf Khaled Hossain, 998891515, shafaaf.hossain@mail.utoronto.ca
#Ismail Hossain, 998340175, ridoy.hossain@mail.utoronto.ca

Sploit 1
We determined where the return address of lab_main() is located on the stack. We then proceeded to create an attack buffer where the first 45 bytes of the attack buffer contain the shellcode, and the last 4 bytes containing the value of the return address we want. This return address value is the start of the attack buffer. strcpy() causes buf to overflow due to the size of the attack buffer and the return address on the stack frame is replaced by the address of the shell code.

Sploit 2
The foo function was copying the input attack buffer of size 285 into a smaller buffer. We had overwritten the return address of foo to the start of the input buffer which contains shellcode. However, in between, the i and length variables need to be overwritten. The i is overwritten such that it gets evaluated to 267. Then we had overwritten length to make it 283 as i starts from 0. The 0x00 bytes are passed in for 283 using the env variables. The env variables are passed in argv variable after the attack buffer reaches a null character.

Sploit 3
The bar function copies the attack buffer onto buf + 4 which was 68 bytes away from the return address. This is because the pointer increments by 4 due to strlen. Thus an additional 4 bytes are needed to overwrite the return address with the address of the buf + 4. The buf + 4 would contain shellcode which would then be executed when the function returns.

Sploit 4
Here the foo function will copy the attack buffer of size 189 onto buf[156]. There are 184 bytes between buf and the return address of foo and so an additional 5 bytes are needed for the overwriting of return address and null character to make a total of 189 bytes. The return address is overwritten with the starting address of buf which contains the shellcode. While overwriting, len is overwritten with 187 and i with 172 to allow it to copy everything. Several null characters are needed and therefore parts of the buffer are passed in with the env variables

Sploit 6
There’s a double free invulnerability here. When making the 2 fake tags in the attack buffer, we made q’s previous be a jump 4 bytes instruction and next being some garbage value.Then the shellcode is entered in. The fake tag of q would have its ‘next’ point to the return address of foo and its previous point to the jump 4 bytes instruction. The jump 4 instruction is used because tfree makes q’s previous’ next point to the return address as that is q’s next. The jump instruction will jump over the random fixed values and into the shell code.
