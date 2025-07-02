# Mycelium
This project contains a kernel-mode driver (meant to be installed as a Windows service) that hooks at a kernel-level the main APIs commonly used by malicious applications. This analysis effort is complemented by an user-mode agent that reads the data collected from the kernel driver and instruments the target binary with hooks for user-mode APIs related to cryptography, registry keys, process/thread creation, network calls.
 
