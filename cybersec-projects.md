# Overview
This page is written to give ideas for projects to help increase comfortability using and developing different open/closed source tools, develop a better understanding of different OS' system internals, and to refine/build workflows for red/blue operations

## General

### General Project: Blog/Personal Site
**Goals**: Develop a personal site or blog to act as a portfolio   
**Resources**:   
- [Github Pages](https://pages.github.com/)
- [Medium](https://medium.com/)

**Recommended Actions**:   
- Create site
- Post something meaningful

**Suggested Output**:   
- A personal cyber security portfolio
 
---
 
### General Project: Phishing/Infrastructure Setup
**Goals**: Increase comfortability with major cloud providers or on-premises infrastructure setup by creating a phishing campaign  

**Resources**:  
- [snaplabs.io](https://dashboard.snaplabs.io/)
- [Evilginx Phising Infrastructure Setup](https://github.com/An0nUD4Y/Evilginx-Phishing-Infra-Setup)
- [Game of Active Directory (GOAD)](https://github.com/Orange-Cyberdefense/GOAD)  

**Recommended Actions**:  
- Setup Snaplabs active directory/email environment or create an on-prem environment using GOAD
- Setup phishing infrastructure (including having a seeded/good reputation domain) either on-prem or in cloud
- Send a phishing message to your developed environment that is filtered
- Send a phishing message to your developed environment that subverts previous filters
- Send a phishing message to a personal email that subverts online email filters

**Suggested Output**:  
- An active directory environment with email capability
- Workflow established for crafting phishing emails and subverting on-prem and online provider filters


## Red Team

### Red Project: PrintNightmare Scanner
**Goals**: Using byt3bl33d3r's "ItWasAllADream" repo, create a standalone and extensible PrintNightmare Scanner python program  

**Resources**:   
- [ItWasAllADream](https://github.com/byt3bl33d3r/ItWasAllADream)
- [Impacket](https://github.com/fortra/impacket)

**Recommended Actions**:   
- Setup a VM which is vulnerable to PrintNightmare
- Setup a VM which is not vulnerable to PrintNightmare
- The program should take input in a single IP, .csv, or new line separated text document
- The program should be able to test via MS-PAR, MS-RPRN, or the UNC bypass
- The repo should have a valid requirements.txt and all other standard python packaging

**Suggested Output**: A github repository of a standalone PrintNightmare Scanner  
 
---
 
### Red Project: Subdomain Enumeration
**Goals**: Identify as many subdomains as possible in a single query  

**Resources**:  
- [bbot](https://github.com/blacklanternsecurity/bbot)
- [Crunchbase](https://www.crunchbase.com/)
- [pymeta](https://github.com/m8sec/pymeta)
- [Crt.sh](https://crt.sh/)
- [DNSDumpster](https://dnsdumpster.com/)

**Recommended Actions**: 
- Take a few large apex domains (e.g. usbank, publix, wells fargo) and view the results from the tools listed above
- Create a solution which automates this process and combines the output
- Identify other available sources for DNS records to obtain a comprehensive list of subdomains


**Suggested Output**: 
- Develop a solution which can provide all subdomains for a given apex domain using as many valid sources as possible
 
---
 
### Red Project: SMB Share Enumeration
**Goals**:  Create an extensible SMB File Share Enumeration program

**Resources**:  
- [SMBCrunch](https://github.com/Raikia/SMBCrunch)
- [Snaffler](https://github.com/SnaffCon/Snaffler)

**Recommended Actions**:  
- Review provided resources
- Enumerate a test environment using both suggested tools
- Combine the parsing logic from Snaffler into the workflow of SMBCrunch and create a fully automated process

**Suggested Output**: Single program which can identify shares, read and write the contents to file, and identify potential access vectors and download the identified files

## Blue Team

### Blue Project: Detection Engineering
**Goals**: Develop robust detections for a chosen MITRE technique

**Resources**: [MADER](https://github.com/blue-armory/MADER)

**Recommended Actions**:   
- Review provided resources
- Follow provided directions

**Suggested Output**: Tested and validated detections for given technique using any open source detection technologies (e.g. ELK, Suricata, Windows Event Logs)  
 
---
 
### Blue Project: Characterize Attack Lifecycle
**Goals**: Perform and detect an entire adversary attack campaign    

**Resources**:     
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [SecurityOnion](https://securityonionsolutions.com/)

**Recommended Actions**:     
- Establish a cloud or on-prem testing environment
- Plan an adversary attack campaign (e.g. ransomware, PII exfiltration, persistent code exfiltration)
- Establish logging and defensive resources (e.g. forward Windows Events to SIEM, setup Velociraptor for EDR)
- Perform attack campaign
- Correlate _ALL_ red actions with discovered artifacts

**Suggested Output**:   
 - Writeup the process in a blog post
---
 
### Blue Project: Beatup Velociraptor
**Goals**: Perform LPE (Local Privilege Escalation) subverting detection from Velociraptor

**Resources**:   
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [SecurityOnion](https://securityonionsolutions.com/)

**Recommended Actions**:   
- Choose a LPE technique
- Perform technique against a test VM
- Perform technique against a test VM with Velociraptor installed
- Perform undetected technique against a test VM with Velociraptor installed

**Suggested Output**:   
- Workflow for subverting EDR with a given LPE technique