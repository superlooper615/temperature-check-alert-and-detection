# Goal
Detect attempts by potentially malicious software to get current temperature of the hardware. 

# Categorization
These attempts are categorized as [Virtualization/Sandbox Evasion / System Checks](https://attack.mitre.org/techniques/T1497/).

# Strategy Abstract
The strategy will function as follows: 

* Record process and process command line information for Windows  hosts using endpoint detection tooling.
* Look for any explicit process or command line requesting hardware temperature, manufacture and BIOS information. 
* Fire alert on any other process or command line activity.

# Technical Context
Wmic.exe is a tool to access Windows Management Instrumentation (WMI). Previously, an end user would generally write a script to gather information by means of WMI. Wmic.exe can only be used by the local system administrators regardless of WMI namespace permissions on the local machine. 

In order to avoid being analysed, [Gravity RAT](https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html) will perform temperature check of the system using Windows Management Instrumentation.Hyper-V, VMWare Fushion, Virtualbox, KVM, , Xen, some Lenovo and Dell models would not return a proper result as indicated below:

![alt text](https://3.bp.blogspot.com/-ifue71YyAug/WucvJRzXCNI/AAAAAAAAAak/8XC3YzAxV1YQ-bvkJUI3fcxvMcVPP3mEgCLcBGAs/s1600/image5.png)

However, a physical host would return actual temperature of the hardware.

![alt text](https://1.bp.blogspot.com/-n20-E-BfwiQ/WucvFfiORUI/AAAAAAAAAag/aWbLDunys9UhfrnvecIOy5z-BeYOLo1JQCLcBGAs/s640/image13.png)

The following screenshot shows the same command as part of a endpoint detection tooling process execution chain: 

Looking at the [source code for GravityRAT](https://github.com/EmpireProject/Empire/blob/8f3570b390d6f91d940881c8baa11e2b2586081a/lib/listeners/http.py) reveals the explicit check using WMI:

![alt text](https://www.mcafee.com/wp-content/uploads/2019/09/code-sample.jpg)
# Blind Spots and Assumptions

This strategy relies on the following assumptions: 
* Endpoint detection tooling is running and functioning correctly on the system.
* Process execution events are being recorded.
* Logs from endpoint detection tooling are reported to the server.
* Endpoint detection tooling is correctly forwarding logs to SIEM.
* SIEM is successfully indexing endpoint detection tooling logs. 
* Attacker toolkits will perform temperature check to verify physical host

A blind spot will occur if any of the assumptions are violated. For instance, the following would not trip the alert: 
* Endpoint detection tooling is tampered with or disabled.
* The attacker implant does not perform temperature check.


# False Positives
There are several instances where false positives for this ADS could occur:

* Legitimite applications measuring the hardware temperature.
* User explitcit check for hardware temperature

Most false positives can be attributed to scripts or user behavior looking at the current current temperature. These are either trusted binaries (e.g. our management tools) or are definitively benign user behavior (e.g. the processes performing interrogation are child processes of a user shell process).

# Priority
The priority is set to medium under all conditions.

# Validation
Validation can occur for this ADS by performing the following execution on a Windows OS host: 
```
wmic /namespace:\\root\WMI path MSAcpi_ThermalZoneTemperature get CurrentTemperature
```

# Response
In the event that this alert fires, the following response procedures are recommended: 

* Look at the process that triggered this alert. Walk the process chain.
  * What process triggered this alert?
  * What was the user the process ran as?
  * What was the parent process?
  * Are there any unusual discrepancies in this chain?
* Look at the process that triggered this alert. Inspect the binary.
  * Is this a shell process?
  * Is the process digitally signed?
  * Is the parent process digitally signed?
  * How prevalent is this binary?
* Does this appear to be user-generated in nature?
  * Is this running in a long-running shell?
  * Are there other indicators this was manually typed by a user?
  * If the activity may have been user-generated, reach out to the user via our chat client and ask them to clarify their behavior.
* If the user is unaware of this behavior, escalate to a security incident.
* If the process behavior seems unusual escalate to a security incident. 

# Additional Resources
* [GravityRAT Malware (Representative Sample)](https://blog.talosintelligence.com/2018/04/gravityrat-two-year-evolution-of-apt.html)

