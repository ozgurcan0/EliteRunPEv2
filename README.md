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
