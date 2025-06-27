# 🧠 Build Your Own Operating System from Scratch (C + Assembly | Windows)

This repository is a step-by-step, beginner-friendly guide for building a basic **Operating System from scratch**, using **C** and **x86 Assembly**, on **Windows 10/11** with **WSL2**.  
You don’t need prior experience with kernels, memory management, or low-level code. Every step is self-contained and executable on its own.

---

## ✅ Step 1: Introduction & Toolchain Setup (WSL2)

### 🔍 What Are We Doing?

Setting up a Windows-based development environment to:
- Write bootloaders in Assembly
- Write kernels in C
- Compile everything using GCC & NASM
- Run our OS in QEMU

---

### 🧰 Tools to Install (via WSL Ubuntu)

```bash
sudo apt update
sudo apt install build-essential nasm qemu-system-x86
```

---

### 📁 Folder Structure

```bash
mkdir -p ~/myos/{bootloader,kernel,iso}
cd ~/myos
```

```
myos/
├── bootloader/
├── kernel/
├── iso/
```

---

### 💻 Sample Bootloader (Print 'H')

`bootloader/boot.asm`:
```asm
BITS 16
ORG 0x7C00

mov ah, 0x0E
mov al, 'H'
int 0x10

jmp $

times 510 - ($ - $$) db 0
dw 0xAA55
```

Compile and run:
```bash
nasm -f bin boot.asm -o boot.bin
qemu-system-i386 -drive format=raw,file=boot.bin
```

✅ You should see the letter `H` on the screen.

---

## ✅ Step 2: Bootloader that Loads a Kernel

### 🔍 What Are We Doing?

Extend the bootloader so it can:
- Load a second stage binary (our kernel) from disk
- Jump into 32-bit protected mode
- Transfer control to the kernel

---

### 📁 Folder Structure

```
myos/
├── bootloader/
│   └── boot.asm
├── kernel/
│   └── kernel.c
├── iso/
```

---

### 🧰 Files to Create

#### `bootloader/boot.asm`
```asm
BITS 16
ORG 0x7C00

; Load kernel (512 bytes) from second sector into memory 0x1000
mov bx, 0x1000
mov dh, 1
mov ah, 0x02
mov al, 1
mov ch, 0
mov cl, 2
mov dl, 0x00
int 0x13

; Switch to 32-bit mode
cli
lgdt [gdt_descriptor]

mov eax, cr0
or eax, 1
mov cr0, eax
jmp CODE_SEG:init_pm

[bits 32]
init_pm:
mov ax, DATA_SEG
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
mov ss, ax
mov esp, 0x90000

jmp 0x08:0x1000

; GDT
gdt_start:
    dq 0x0000000000000000
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
gdt_descriptor:
    dw 23
    dd gdt_start

CODE_SEG equ 0x08
DATA_SEG equ 0x10

times 510-($-$$) db 0
dw 0xAA55
```

---

### 🧪 Compile and Run

```bash
# Bootloader
cd ~/myos/bootloader
nasm -f bin boot.asm -o boot.bin
```

To test this fully, you need a simple kernel first (see Step 3), then combine both:

```bash
cat boot.bin ../kernel/kernel.bin > ../iso/os-image.bin
qemu-system-i386 -drive format=raw,file=../iso/os-image.bin
```

✅ You should see kernel output (e.g. "Hello from C kernel").

---

## ✅ Step 3: Writing a Barebones C Kernel

### 🔍 What Are We Doing?

Write a 32-bit protected mode kernel in **C**, and link it into a flat binary that gets loaded by the bootloader.

---

### 💻 File: `kernel/kernel.c`

```c
void kernel_main() {
    const char* str = "Hello from C kernel!";
    char* vga = (char*) 0xB8000;
    for (int i = 0; str[i] != '\0'; i++) {
        vga[i * 2] = str[i];
        vga[i * 2 + 1] = 0x07; // White text
    }

    while (1); // Halt CPU
}
```

---

### 🧰 File: `kernel/link.ld`

```ld
ENTRY(kernel_main)

SECTIONS {
    . = 0x1000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
}
```

---

### 🧪 Compile Kernel

```bash
cd ~/myos/kernel

# Compile kernel
gcc -m32 -ffreestanding -c kernel.c -o kernel.o
ld -m elf_i386 -T link.ld -o kernel.bin kernel.o --oformat binary
```

✅ This produces `kernel.bin`, which the bootloader will load at `0x1000`.

---

## ✅ Step 4: Simple Command Prompt (Input Echo)

### 🔍 What Are We Doing?

Add basic keyboard input support and print typed characters (like a mini shell).

---

### 💻 Edit `kernel/kernel.c`

```c
#include <stdint.h>

volatile char* vga = (char*) 0xB8000;
int cursor = 0;

void print_char(char c) {
    vga[cursor++] = c;
    vga[cursor++] = 0x07;
}

char get_key() {
    uint8_t key;
    asm volatile (
        "in al, 0x60"
        : "=a"(key)
    );
    return key;
}

void kernel_main() {
    const char* msg = "Type below:\n";
    for (int i = 0; msg[i]; i++) print_char(msg[i]);

    while (1) {
        uint8_t scancode;
        asm volatile ("inb $0x60, %0" : "=a"(scancode));

        if (scancode & 0x80) continue;

        char c = '?';
        if (scancode == 0x1E) c = 'a';
        else if (scancode == 0x30) c = 'b';
        else if (scancode == 0x20) c = 'd';
        // ... Add more keys as needed

        print_char(c);
    }
}
```

✅ Typing keys should show them on screen.

---

## ✅ Step 5: System Calls (Software Interrupts)

### 🔍 What Are We Doing?

Implement `int 0x80`-based syscall interface for user-kernel communication.

---

### 💻 Kernel syscall handler
```c
void syscall_handler() {
    print_char('S');
}

void kernel_main() {
    // Set syscall handler
    // In real OS, you'd set IDT entry for 0x80
    asm volatile (
        "mov $syscall_handler, %eax;"
        "int $0x80;"
    );
}
```

📝 To fully support this, you'll later need to write an IDT and interrupt service routine (future step).

---

## ✅ Step 6: Dynamic Memory Allocation (First Fit)

### 🔍 What Are We Doing?

Write a simple `malloc` that uses first-fit strategy.

---

### 💻 `heap.c`

```c
#include <stddef.h>
#define HEAP_START 0x100000

typedef struct block {
    size_t size;
    struct block* next;
    int free;
} block_t;

block_t* head = (block_t*) HEAP_START;

void init_heap() {
    head->size = 1024;
    head->next = NULL;
    head->free = 1;
}

void* malloc(size_t n) {
    block_t* curr = head;
    while (curr) {
        if (curr->free && curr->size >= n) {
            curr->free = 0;
            return (void*)(curr + 1);
        }
        curr = curr->next;
    }
    return NULL;
}
```

✅ You now have basic memory allocation working in protected mode!

---

## ✅ Step 7: Spinlocks and Sleeplocks

### 🔍 What Are We Doing?

Create basic lock primitives.

---

### 💻 `locks.h`

```c
typedef volatile int lock_t;

void init_lock(lock_t* lock) {
    *lock = 0;
}

void spin_lock(lock_t* lock) {
    while (__sync_lock_test_and_set(lock, 1)) {}
}

void spin_unlock(lock_t* lock) {
    __sync_lock_release(lock);
}
```

✅ Use these to protect access to shared memory.

---

## 🔬 Bonus: Tests (FOS-Style)

- Test dynamic allocation:
```c
void test_alloc() {
    void* a = malloc(100);
    void* b = malloc(100);
    assert(a != NULL && b != NULL);
}
```

- Add more tests later using keyboard I/O or VGA output.

---

## ✅ You're Done!

You now have:
- A bootloader that loads a C kernel
- A working kernel with VGA text output
- Keyboard input
- Basic system calls
- Dynamic memory allocation
- Locks for concurrency

---

---

## ✅ Step 8: Interrupt Descriptor Table (IDT)

### 🔍 What Are We Doing?

We’re setting up the **IDT** so we can handle:
- Exceptions (e.g., divide by zero)
- Hardware interrupts (e.g., keyboard, timer)
- System calls (e.g., `int 0x80`)

---

### 💻 `kernel/idt.c`

```c
#include <stdint.h>

#define IDT_SIZE 256

struct idt_entry {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t  zero;
    uint8_t  type_attr;
    uint16_t offset_high;
} __attribute__((packed));

struct idt_ptr {
    uint16_t limit;
    uint32_t base;
} __attribute__((packed));

struct idt_entry idt[IDT_SIZE];
struct idt_ptr idtp;

extern void load_idt(struct idt_ptr*);

void set_idt_gate(int n, uint32_t handler) {
    idt[n].offset_low = handler & 0xFFFF;
    idt[n].selector = 0x08;
    idt[n].zero = 0;
    idt[n].type_attr = 0x8E; // Present, ring 0, 32-bit interrupt gate
    idt[n].offset_high = (handler >> 16) & 0xFFFF;
}

void init_idt() {
    idtp.limit = (sizeof(struct idt_entry) * IDT_SIZE) - 1;
    idtp.base = (uint32_t)&idt;

    for (int i = 0; i < IDT_SIZE; i++)
        set_idt_gate(i, (uint32_t)isr_default);

    load_idt(&idtp);
}
```

---

### 💻 `kernel/idt.asm` (Assembly ISR stub + loader)

```asm
[bits 32]

global isr_default
global load_idt

isr_default:
    pusha
    mov al, '!'
    mov ah, 0x0E
    int 0x10
    popa
    iret

load_idt:
    mov eax, [esp + 4]
    lidt [eax]
    ret
```

---

### 💻 Modify `link.ld` to include IDT

Add `.idt` section:
```ld
SECTIONS {
    . = 0x1000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    .idt : { *(.idt*) }
}
```

---

### 🧪 Compile and Link

```bash
cd ~/myos/kernel

# Compile
gcc -m32 -ffreestanding -c kernel.c -o kernel.o
gcc -m32 -ffreestanding -c idt.c -o idt.o
nasm -f elf idt.asm -o idt_asm.o

# Link
ld -m elf_i386 -T link.ld -o kernel.bin kernel.o idt.o idt_asm.o --oformat binary
```

✅ If the IDT is correctly installed, pressing keys or causing exceptions (like divide by zero) will show a `'!'` character onscreen, indicating the handler fired.

---

### ⚠️ Common Mistakes to Avoid

- ❌ Forgetting to call `init_idt()` from `kernel_main()`
- ❌ Forgetting `extern` declaration for `load_idt` or `isr_default`
- ❌ Missing `iret` at the end of your ISR handler

---

✅ Now your OS can handle **interrupts** and will be able to support hardware (like keyboard & timer) and **system calls** cleanly in later steps.

---

## ✅ Step 9: PIC Remapping & Timer Interrupt (IRQ0)

### 🔍 What Are We Doing?

Before we can handle hardware interrupts (like the keyboard or timer), we must **remap the PIC** (Programmable Interrupt Controller), because:
- By default, IRQs 0–15 overlap CPU exception vectors (0x00–0x1F).
- We remap them to safe IDT entries (0x20–0x2F).
- Then we install a **timer interrupt handler** at IRQ0 (mapped to IDT[32]).

---

### 💻 `kernel/pic.c` — Remap PIC

```c
#include <stdint.h>

#define PIC1 0x20
#define PIC2 0xA0
#define PIC1_COMMAND PIC1
#define PIC1_DATA    (PIC1+1)
#define PIC2_COMMAND PIC2
#define PIC2_DATA    (PIC2+1)

#define ICW1_INIT     0x10
#define ICW1_ICW4     0x01
#define ICW4_8086     0x01

void outb(uint16_t port, uint8_t val) {
    asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}

void pic_remap() {
    outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
    outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);

    outb(PIC1_DATA, 0x20); // PIC1 mapped to 0x20–0x27
    outb(PIC2_DATA, 0x28); // PIC2 mapped to 0x28–0x2F

    outb(PIC1_DATA, 0x04);
    outb(PIC2_DATA, 0x02);

    outb(PIC1_DATA, ICW4_8086);
    outb(PIC2_DATA, ICW4_8086);

    outb(PIC1_DATA, 0x0);
    outb(PIC2_DATA, 0x0);
}
```

---

### 💻 `kernel/timer.c` — IRQ0 Timer Handler

```c
#include <stdint.h>
#include "idt.h"

uint32_t tick = 0;

void timer_callback() {
    tick++;
    // Optional: print something every X ticks
}

__attribute__((interrupt))
void timer_isr(void* frame) {
    timer_callback();
    outb(0x20, 0x20); // Send EOI (End of Interrupt)
}
```

---

### 💻 `kernel/idt.h` — Register IRQs

```c
void set_idt_gate(int n, uint32_t handler);
void init_idt();
```

---

### 💻 `kernel/main.c` (or `kernel.c`)

Add:
```c
extern void timer_isr();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(32, (uint32_t)timer_isr);

    // Enable interrupts
    asm volatile ("sti");

    while (1);
}
```

---

### 💻 `kernel/link.ld` (ensure all files are linked)

Make sure all files are included in your link command:
```bash
ld -m elf_i386 -T link.ld -o kernel.bin kernel.o idt.o idt_asm.o pic.o timer.o --oformat binary
```

---

### 🧪 Run & Test

You should now:
- See no crash
- Be able to place a `print_char('*');` inside `timer_callback()` and watch it print every few ticks

---

### ⚠️ Common Mistakes to Avoid

- ❌ Forgetting to call `pic_remap()` **before** enabling IRQs
- ❌ Forgetting to send End of Interrupt (EOI) in `timer_isr`
- ❌ Using a handler without `__attribute__((interrupt))` on newer GCC

---

✅ You now have working **hardware interrupts** and a **programmable timer**, which are critical for preemptive multitasking, clocks, and scheduling!
---

## ✅ Step 10: Keyboard Driver with IRQ1

### 🔍 What Are We Doing?

Now that the PIC and IDT are set up, we're adding:
- An **IRQ1 handler** to capture keyboard input
- A basic **scancode-to-ASCII** translation
- VGA text printing of typed keys

---

### 💻 `kernel/keyboard.c` — Basic Keyboard Handler

```c
#include <stdint.h>
#include "idt.h"

extern void print_char(char);

char scancode_to_ascii[128] = {
    0,  27, '1','2','3','4','5','6','7','8','9','0','-','=','\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n', 0,
    'a','s','d','f','g','h','j','k','l',';','\'','`',  0,'\\',
    'z','x','c','v','b','n','m',',','.','/',  0, '*', 0, ' '
    // (only basic chars for now)
};

__attribute__((interrupt))
void keyboard_isr(void* frame) {
    uint8_t scancode;
    asm volatile ("inb $0x60, %0" : "=a"(scancode));

    if (scancode < 128) {
        char c = scancode_to_ascii[scancode];
        if (c) print_char(c);
    }

    // Acknowledge IRQ1
    asm volatile ("outb %0, %1" : : "a"(0x20), "Nd"(0x20));
}
```

---

### 💻 `kernel/print.c` — VGA Text Output Helper

```c
#include <stdint.h>

volatile char* vga = (char*) 0xB8000;
int cursor = 0;

void print_char(char c) {
    if (c == '\n') {
        cursor = (cursor / 160 + 1) * 160;
    } else {
        vga[cursor++] = c;
        vga[cursor++] = 0x07;
    }
}
```

---

### 💻 Update `kernel/main.c`

```c
extern void keyboard_isr();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(32, (uint32_t)timer_isr);    // IRQ0: Timer
    set_idt_gate(33, (uint32_t)keyboard_isr); // IRQ1: Keyboard

    asm volatile ("sti");

    print_char('\n');
    print_char('>');

    while (1);
}
```

---

### 🧪 Compile & Link

```bash
gcc -m32 -ffreestanding -c keyboard.c -o keyboard.o
gcc -m32 -ffreestanding -c print.c -o print.o
ld -m elf_i386 -T link.ld -o kernel.bin \
    kernel.o idt.o idt_asm.o pic.o timer.o keyboard.o print.o --oformat binary
```

---

### ✅ Test: Run with QEMU

```bash
qemu-system-i386 -drive format=raw,file=iso/os-image.bin
```

Start typing — letters should appear after the `>` prompt. Newlines and basic characters will work!

---

### ⚠️ Common Mistakes to Avoid

- ❌ Not enabling interrupts (`sti`)
- ❌ Forgetting to acknowledge IRQ1 (`outb 0x20, 0x20`)
- ❌ Using wrong scancode map or missing array bounds

---

✅ You now have a basic **keyboard driver** using IRQ1 and can **echo keystrokes** in your OS — your first interactive feature!
---

## ✅ Step 11: Page Fault Handling

### 🔍 What Are We Doing?

Paging is already enabled (Step 8), but now we’ll:
- Set up a handler for **page fault exceptions** (interrupt 14)
- Print diagnostic info (faulting address, error code)
- Prevent silent kernel crashes on memory errors

---

### 💻 `kernel/pagefault.c` — Page Fault ISR

```c
#include <stdint.h>

extern void print_char(char);
extern void print_hex(uint32_t);

__attribute__((interrupt))
void page_fault_handler(void* frame, uint32_t error_code) {
    print_char('\n');
    print_char('[');
    print_char('P');
    print_char('F');
    print_char(']');
    print_char(' ');

    uint32_t fault_addr;
    asm volatile("mov %%cr2, %0" : "=r"(fault_addr));
    print_hex(fault_addr);

    while (1); // Halt
}
```

---

### 💻 `kernel/print.c` — Add `print_hex` Helper

```c
void print_hex(uint32_t num) {
    const char* hex = "0123456789ABCDEF";
    print_char('0');
    print_char('x');
    for (int i = 28; i >= 0; i -= 4)
        print_char(hex[(num >> i) & 0xF]);
}
```

---

### 💻 Modify `kernel/main.c`

```c
extern void page_fault_handler();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(14, (uint32_t)page_fault_handler); // Page fault
    set_idt_gate(32, (uint32_t)timer_isr);
    set_idt_gate(33, (uint32_t)keyboard_isr);

    asm volatile ("sti");

    print_char('\n');
    print_char('>');
}
```

---

### 🧪 Trigger a Page Fault (Test)

In `kernel_main`, add:

```c
*(int*)0xDEADBEEF = 42; // Invalid memory write
```

✅ You should see:
```
[PF] 0xDEADBEEF
```

---

### ⚠️ Common Mistakes to Avoid

- ❌ Forgetting to register the handler to IDT[14]
- ❌ Forgetting to read `cr2` register for fault address
- ❌ Missing second argument `uint32_t error_code` in `__attribute__((interrupt))` handlers for fault ISRs

---

✅ You now have a working **page fault handler** and can **safely debug memory issues** in your OS!
---

## ✅ Step 12: Switching to User Mode (Ring 3)

### 🔍 What Are We Doing?

We’ll switch from **kernel mode (Ring 0)** to **user mode (Ring 3)** so:
- User programs can't directly access hardware or kernel memory
- System calls become the only way to interact with the kernel

---

### 💡 How?

We use an `iret` trick to pop CS, SS, and EFLAGS with Ring 3 privilege, jumping to a safe user-space function.

---

### 💻 `kernel/user.c` — User Mode Entry Stub

```c
void user_mode_main() {
    const char* msg = "Hello from User Mode!";
    volatile char* vga = (char*)0xB8000 + 160;
    for (int i = 0; msg[i]; i++) {
        vga[i * 2] = msg[i];
        vga[i * 2 + 1] = 0x1F; // White on blue
    }

    while (1);
}
```

---

### 💻 `kernel/user.asm` — Switch Function

```asm
[bits 32]
global switch_to_user_mode
extern user_mode_main

switch_to_user_mode:
    cli

    ; Set data segments to ring 3 (0x23)
    mov ax, 0x23
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Push user-mode segment selectors
    push 0x23         ; SS
    push 0x90000      ; ESP
    pushf             ; EFLAGS
    push 0x1B         ; CS (0x18 | 3)
    push user_mode_main
    iret
```

---

### 💻 GDT Update (`boot.asm` or `gdt.asm`)

Make sure your GDT includes **Ring 3 segments**:

```asm
gdt_start:
    dq 0x0000000000000000         ; Null
    dq 0x00CF9A000000FFFF         ; Code Segment (0x08)
    dq 0x00CF92000000FFFF         ; Data Segment (0x10)
    dq 0x00CFFA000000FFFF         ; User Code (0x18)
    dq 0x00CFF2000000FFFF         ; User Data (0x20)
gdt_descriptor:
    dw 39
    dd gdt_start
```

---

### 💻 Update `kernel/main.c`

```c
extern void switch_to_user_mode();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(14, (uint32_t)page_fault_handler);
    set_idt_gate(32, (uint32_t)timer_isr);
    set_idt_gate(33, (uint32_t)keyboard_isr);

    asm volatile ("sti");

    print_char('\n');
    print_char('U');

    switch_to_user_mode();
}
```

---

### 🧪 Compile & Link

```bash
nasm -f elf user.asm -o user.o
gcc -m32 -ffreestanding -c user.c -o user_c.o
ld -m elf_i386 -T link.ld -o kernel.bin \
  kernel.o idt.o idt_asm.o pic.o timer.o keyboard.o print.o \
  pagefault.o user_c.o user.o --oformat binary
```

---

### ✅ Result

You should now:
- See a blue line with `"Hello from User Mode!"` below the kernel prompt
- Your CPU is now in **Ring 3**, and future system calls must go through `int 0x80`

---

### ⚠️ Common Mistakes to Avoid

- ❌ Not using the correct GDT privilege levels (user = 3)
- ❌ Not pushing SS, ESP, EFLAGS, CS, EIP in order
- ❌ Forgetting to align stack or pushing wrong selectors

---

✅ Your OS now **separates user-space and kernel-space**, a major milestone toward **real multitasking and secure system call interfaces**!

---

## ✅ Step 13: System Calls with Arguments (`int 0x80`)

### 🔍 What Are We Doing?

We’re implementing a basic **system call interface** using the `int 0x80` interrupt:
- User mode programs use `int 0x80` to request kernel services
- Arguments passed through registers (e.g., `eax`, `ebx`, `ecx`, `edx`)
- Kernel handles calls via a **syscall table**

---

### 💻 `kernel/syscall.c` — Syscall Handler

```c
#include <stdint.h>
#include "print.h"

void sys_write_char(char c) {
    print_char(c);
}

void sys_print_string(const char* str) {
    while (*str) sys_write_char(*str++);
}

// Syscall numbers
enum {
    SYSCALL_WRITE_CHAR = 0,
    SYSCALL_PRINT_STRING = 1,
};

__attribute__((interrupt))
void syscall_handler(void* frame) {
    uint32_t syscall_num, arg1;

    asm volatile("mov %%eax, %0" : "=r"(syscall_num));
    asm volatile("mov %%ebx, %0" : "=r"(arg1));

    switch (syscall_num) {
        case SYSCALL_WRITE_CHAR:
            sys_write_char((char)arg1);
            break;
        case SYSCALL_PRINT_STRING:
            sys_print_string((const char*)arg1);
            break;
        default:
            print_string("[sys] Unknown syscall\n");
    }
}
```

---

### 💻 Update `kernel/main.c`

```c
extern void syscall_handler();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(14, (uint32_t)page_fault_handler);
    set_idt_gate(32, (uint32_t)timer_isr);
    set_idt_gate(33, (uint32_t)keyboard_isr);
    set_idt_gate(0x80, (uint32_t)syscall_handler); // System calls

    asm volatile ("sti");

    print_string("Kernel Loaded\n");
    switch_to_user_mode();
}
```

---

### 💻 Update `user.c` — Make a Syscall from User Mode

```c
void user_mode_main() {
    const char* msg = "Syscall from user mode!\n";

    asm volatile (
        "mov $1, %%eax\n"        // syscall number: print string
        "mov %0, %%ebx\n"        // argument: pointer to string
        "int $0x80\n"
        :
        : "r"(msg)
        : "eax", "ebx"
    );

    while (1);
}
```

---

### 💻 `print.h` — Expose Print API to Other Kernel Files

```c
#ifndef PRINT_H
#define PRINT_H

void print_char(char c);
void print_string(const char* str);
void print_hex(uint32_t num);

#endif
```

---

### 🧪 Compile & Link

```bash
gcc -m32 -ffreestanding -c syscall.c -o syscall.o
ld -m elf_i386 -T link.ld -o kernel.bin \
  kernel.o idt.o idt_asm.o pic.o timer.o keyboard.o print.o \
  pagefault.o user_c.o user.o syscall.o --oformat binary
```

---

### ✅ Test Output

You should see:
```
Kernel Loaded
Syscall from user mode!
```

Printed by a user-space function calling `int 0x80` into the kernel!

---

### ⚠️ Common Mistakes to Avoid

- ❌ Not setting up `int 0x80` in the IDT
- ❌ Using wrong calling convention (use `eax`, `ebx`, etc.)
- ❌ Not marking syscall handler with `__attribute__((interrupt))`

---

✅ You now have a working **syscall interface**, which lets **user programs request safe kernel services** — the foundation for any modern OS!

---

## ✅ Step 14: ELF Binary Loader (Load User Programs from Disk)

### 🔍 What Are We Doing?

Now that we can switch to user mode and handle syscalls, we’ll:
- Parse **ELF binaries** (standard Linux format) from disk or memory
- Extract their entry point and load code segments
- Jump into them from kernel space

---

### 💡 Why ELF?

ELF is a common, modular binary format used by Linux and GCC — supporting:
- Sections (code, data)
- Symbol tables
- Dynamic linking (not used here)

---

### 🧰 Assumptions

- You already loaded a file into memory (e.g., at `0x200000`)
- It was compiled as a 32-bit statically linked ELF using `gcc -m32`

---

### 💻 `kernel/elf.c` — Minimal ELF Parser

```c
#include <stdint.h>

#define ELF_MAGIC 0x464C457F // "\x7FELF" in little endian

typedef struct {
    uint32_t magic;
    uint8_t  elf[12];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint32_t entry;
    uint32_t phoff;
    uint32_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    // Skipping rest for now
} elf_header_t;

typedef struct {
    uint32_t type;
    uint32_t offset;
    uint32_t vaddr;
    uint32_t paddr;
    uint32_t filesz;
    uint32_t memsz;
    uint32_t flags;
    uint32_t align;
} elf_program_header_t;

int load_elf(void* binary) {
    elf_header_t* header = (elf_header_t*)binary;

    if (header->magic != ELF_MAGIC)
        return -1;

    elf_program_header_t* ph = (elf_program_header_t*)((uint8_t*)binary + header->phoff);

    for (int i = 0; i < header->phnum; i++) {
        void* src = (uint8_t*)binary + ph[i].offset;
        void* dest = (void*)ph[i].vaddr;

        for (uint32_t j = 0; j < ph[i].filesz; j++)
            ((uint8_t*)dest)[j] = ((uint8_t*)src)[j];

        for (uint32_t j = ph[i].filesz; j < ph[i].memsz; j++)
            ((uint8_t*)dest)[j] = 0;
    }

    return header->entry;
}
```

---

### 💻 Update `kernel/main.c` — Jump to User Program

```c
extern int load_elf(void* binary);

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(14, (uint32_t)page_fault_handler);
    set_idt_gate(32, (uint32_t)timer_isr);
    set_idt_gate(33, (uint32_t)keyboard_isr);
    set_idt_gate(0x80, (uint32_t)syscall_handler);

    asm volatile ("sti");

    print_string("Kernel Loaded\n");

    void* binary = (void*)0x200000; // Assume ELF binary loaded here
    int entry = load_elf(binary);
    if (entry < 0) {
        print_string("Invalid ELF binary.\n");
        while (1);
    }

    // Set user segments
    asm volatile (
        "cli;"
        "mov $0x23, %%ax;"
        "mov %%ax, %%ds;"
        "mov %%ax, %%es;"
        "mov %%ax, %%fs;"
        "mov %%ax, %%gs;"

        "push $0x23;"         // SS
        "push $0x90000;"      // ESP
        "pushf;"
        "push $0x1B;"         // CS
        "push %0;"
        "iret;"
        :
        : "r"(entry)
    );
}
```

---

### 💻 Compile a User ELF Program

```c
// userprog.c
void main() {
    const char* str = "Hello from loaded ELF!\n";
    asm volatile (
        "mov $1, %%eax;"
        "mov %0, %%ebx;"
        "int $0x80;"
        :
        : "r"(str)
    );
    while (1);
}
```

```bash
gcc -m32 -nostdlib -ffreestanding -o userprog.elf userprog.c
```

---

### 💡 Load ELF into Memory

For now, just embed it manually in `bootloader` or write a simple FAT12 loader (Step 15).

To test manually:

```bash
dd if=userprog.elf of=os-image.bin bs=512 seek=20 conv=notrunc
```

In bootloader (Step 2), read extra sectors into `0x200000`.

---

### ⚠️ Common Mistakes to Avoid

- ❌ Not checking ELF magic (0x7F 'E' 'L' 'F')
- ❌ Not copying both file and memory size
- ❌ Forgetting to set correct segments and privilege level before `iret`

---

✅ You now have a working **ELF loader** and can run user programs dynamically from disk — unlocking modular apps in your OS!


---

## ✅ Step 15: Shell Interface (Mini Command Prompt)

### 🔍 What Are We Doing?

Now that we can:
- Handle keyboard input
- Print to screen
- Switch to user mode
- Handle syscalls

Let’s tie it all together by building a **basic shell** that:
- Accepts text commands
- Matches them against known ones
- Executes actions (e.g., print, clear, halt)

---

### 💡 Feature Goals

- Prompt: `os> `
- Commands: `help`, `clear`, `halt`, `echo [msg]`
- Invalid input: `"Unknown command"`

---

### 💻 `kernel/shell.c` — Command Parser

```c
#include "print.h"
#include <stdint.h>

#define INPUT_MAX 128

char input[INPUT_MAX];
int input_index = 0;

void clear_screen() {
    for (int i = 0; i < 80 * 25 * 2; i++) {
        ((char*)0xB8000)[i] = 0;
    }
}

void prompt() {
    print_string("os> ");
    input_index = 0;
}

void handle_command(const char* cmd) {
    if (strcmp(cmd, "help") == 0) {
        print_string("Commands: help, clear, halt, echo\n");
    } else if (strcmp(cmd, "clear") == 0) {
        clear_screen();
    } else if (strcmp(cmd, "halt") == 0) {
        print_string("Halting...\n");
        asm volatile ("cli; hlt");
    } else if (strncmp(cmd, "echo ", 5) == 0) {
        print_string(cmd + 5);
        print_char('\n');
    } else {
        print_string("Unknown command\n");
    }
}
```

---

### 💻 Extend `keyboard_isr()` in `keyboard.c`

```c
extern char input[];
extern int input_index;
extern void handle_command(const char*);
extern void prompt();

__attribute__((interrupt))
void keyboard_isr(void* frame) {
    uint8_t scancode;
    asm volatile ("inb $0x60, %0" : "=a"(scancode));

    if (scancode & 0x80) return; // Key release

    char c = scancode_to_ascii[scancode];
    if (c == '\n' || scancode == 0x1C) { // Enter
        input[input_index] = '\0';
        print_char('\n');
        handle_command(input);
        prompt();
    } else if (scancode == 0x0E) { // Backspace
        if (input_index > 0) {
            input_index--;
            print_char('\b');
        }
    } else if (c && input_index < 127) {
        input[input_index++] = c;
        print_char(c);
    }

    asm volatile ("outb %0, %1" : : "a"(0x20), "Nd"(0x20));
}
```

---

### 💻 `kernel/string.c` — Simple String Helpers

```c
int strcmp(const char* a, const char* b) {
    while (*a && (*a == *b)) a++, b++;
    return *(const unsigned char*)a - *(const unsigned char*)b;
}

int strncmp(const char* a, const char* b, int n) {
    while (n-- && *a && (*a == *b)) a++, b++;
    return n < 0 ? 0 : *(const unsigned char*)a - *(const unsigned char*)b;
}
```

---

### 💻 Update `kernel/main.c`

```c
extern void prompt();

void kernel_main() {
    init_idt();
    pic_remap();
    set_idt_gate(14, (uint32_t)page_fault_handler);
    set_idt_gate(32, (uint32_t)timer_isr);
    set_idt_gate(33, (uint32_t)keyboard_isr);
    set_idt_gate(0x80, (uint32_t)syscall_handler);

    asm volatile ("sti");

    print_string("SimpleOS Shell\n");
    prompt();

    while (1);
}
```

---

### 🧪 Compile & Link

```bash
gcc -m32 -ffreestanding -c shell.c -o shell.o
gcc -m32 -ffreestanding -c string.c -o string.o
ld -m elf_i386 -T link.ld -o kernel.bin \
  kernel.o idt.o idt_asm.o pic.o timer.o keyboard.o print.o \
  pagefault.o syscall.o shell.o string.o --oformat binary
```

---

### ✅ Test: Run Shell

Run QEMU and type:

```txt
os> help
Commands: help, clear, halt, echo

os> echo hello
hello

os> clear

os> halt
```

---

### ⚠️ Common Mistakes to Avoid

- ❌ Not null-terminating the input string
- ❌ Forgetting to re-show the prompt after each command
- ❌ Not handling backspace properly

---

✅ You now have an **interactive shell** in your OS — capable of parsing input, handling commands, and executing real actions!

