#Computer Security

For more info, read explanations text file which are under every lab directory.

## Lab 1 
Parts 1 to 4 are about buffer overflows and compulsary for full completion of the lab. There also bonus parts which include format string invulnerabilites as part 5, and double free vulnerabilities as part 6.
The objective of these labs was to craft a buffer overflow attack to change the return address to point to injected shellcode.

- Finished parts 1-4 about buffer overflows
- Finished part 6 about double free attack
- Have my notes which have diagrams of stack, heap, addresses, attack buffers and offsets from each other
- To run, compile the sploit and its corresponding target in the targets folder, and just do ./sploit(which part)

## Lab 2
Used openssl to secure	the	communication	channel	between	the	client	and	the	server. The	client	and	server	will	send messages	over	the	encrypted	channel	that is	set	up	with	SSL.
- To run the server compile it and enter: ./server (port)
- To run the client compile it and enter: ./client (host) (port)

## Lab 3
Generate and validate one-time passwords that are compatible with Google Authenticator. The purpose of this assignment is to be familiarized with both two-factor authentication and HMACs.
Part 1 is to generate an otpauth:// URI to get a barcode that can be scanned to get the HMAC-based One-Time Password (HOTP) and the Time-based One-Time Password (TOTP).
Part 2 is to validate the HOTP and TOTP values entered by the user are correct or not. In order to verify the values, we had to use the SHA1 function to create an HMAC.
- To generate the otpauth and barcode, enter ./generateQRcode "Issuer" "Account Name" "Secret in hex"
For example, $ ./generateQRcode ECE568 gibson 12345678901234567890. Then scan the barcode using the Google Authenticator app.
- To validate the codes, enter ./validateQRcode "Secret in hex" "HOTP passcode" "TOTP passcode"
For example, ./validateQRcode 12345678901234567890 803282 134318
