# EliteRunPEv2

## Description
EliteRunPEv2 is a tool designed for advanced process injection techniques, including process hollowing and payload encryption. The tool is capable of dynamically selecting target processes, injecting encrypted payloads, and hiding traces of the injected code from the operating system. It employs advanced anti-debugging and anti-VM checks to avoid detection.

## Features
- **Process Hollowing**: Injects code into a target process by unmapping the process' image and replacing it with custom code.
- **Payload Encryption**: Uses XOR-based encryption with polymorphic techniques to encrypt payloads.
- **Anti-Analysis**: Includes multiple checks to detect and avoid running in hostile environments such as sandboxes or debuggers.
- **Memory Injection**: Payloads are injected in chunks, simulating legitimate memory activity.
- **APC Stub Injection**: Uses APC (Asynchronous Procedure Call) for hidden execution of the payload.
- **Dynamic Execution**: Features like dynamic delay generation and randomization of memory offsets to evade detection.

## Requirements
- Windows OS (x64 architecture)
- .NET Framework (Target framework .NET Core or higher)
- Administrative privileges may be required for process manipulation

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/ozgurcan0/EliteRunPEv2.git

   # EliteRunPEv2 - Process Hollowing and Payload Injection Tool

**EliteRunPEv2** is a tool designed for **security research** and **malware analysis**. It demonstrates **process hollowing** and **payload injection** techniques to simulate how malicious payloads can be injected into running processes. This code is for **educational purposes** only and should be used only in controlled, isolated environments like virtual machines or sandboxes. **It should not be used for malicious activities or unauthorized access** to systems.

---

## Table of Contents

- [Requirements](#requirements)
- [Setup Instructions](#setup-instructions)
- [How to Use](#how-to-use)
- [Security Considerations](#security-considerations)
- [Disclaimer](#disclaimer)

---

## Requirements

- **.NET Framework**: This code is written in C# and uses the .NET framework, so ensure you have **.NET Framework 4.x** or higher installed on your machine.
- **Visual Studio**: It's recommended to use Visual Studio or any other C# compatible IDE to compile and run the code.
- **Target Process**: The tool will inject the payload into a target process. By default, the process to be targeted is randomly selected from a list of common system processes (e.g., `svchost.exe`, `explorer.exe`, `notepad.exe`).

---

## Setup Instructions

1. **Clone the Repository or Download the Code**:
   Clone or download the repository where the `EliteRunPEv2` code is stored.

2. **Open the Project**:
   Open the solution file (`.sln`) in **Visual Studio** or any other C# IDE.

3. **Configure the Payload**:
   - The `rawPayload` array in the `Main()` method needs to be filled with the byte array of the payload you want to inject. This is typically a compiled PE (Portable Executable) file (e.g., `.exe`, `.dll`).
   - You can use tools like **CFF Explorer** or **PE-bear** to inspect and extract raw payloads for injection.

4. **Build the Project**:
   - Build the project to compile the code into an executable.

5. **Ensure a Test Environment**:
   - Use a **sandbox** or a **virtual machine** to run the compiled executable safely. Make sure that the test environment is isolated from your production system to avoid any potential damage.

---

## How to Use

1. **Run the Executable**:
   - Once the project is compiled, run the generated `.exe` file on a **virtual machine** or a **test machine** that is isolated from your main system.
   
2. **Target Process**:
   - By default, the code selects a target process such as `svchost.exe`, `notepad.exe`, or `explorer.exe`.
   - The target process can be modified in the `SelectTargetProcess` method, which returns the process name to be targeted for payload injection.

3. **Payload Injection**:
   - The payload (PE file) is injected into the target process, with a series of operations like memory allocation, writing to memory, and adjusting the process's thread context to execute the payload.

4. **Observe the Results**:
   - Monitor the target process and the system for any changes or behavior related to the injected payload. This can be useful for analyzing payload functionality, bypass techniques, and anti-debugging strategies.

---

## Security Considerations

- **Test Only in Safe Environments**: This tool must only be used in **isolated environments** (e.g., virtual machines, sandboxes) where it can be safely observed without causing harm to production systems or personal data.
- **Do Not Use for Malicious Purposes**: This tool is intended for educational use and testing within authorized environments. Using it in unauthorized environments or for malicious purposes is illegal and unethical.
- **Antivirus and EDR Detection**: This code may be flagged by antivirus programs and endpoint detection and response (EDR) systems. Use this tool responsibly and only in environments where detection is acceptable for research purposes.

---

## Disclaimer

- **Ethical Use**: This tool is designed for educational purposes and should be used by security professionals, researchers, and ethical hackers who understand the implications of using such software.
- **Legal Warning**: The use of this tool for unauthorized access to computer systems or data is illegal. Ensure you have explicit permission to run tests on any system or network.
- **No Liability**: The creator of this tool is not responsible for any damages, loss of data, or legal consequences resulting from the misuse of this software.

---

**Important**: Always follow best practices and legal guidelines when conducting any security research or penetration testing.

