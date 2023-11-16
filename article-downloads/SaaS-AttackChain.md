# SaaS Attack Chain
## Links
- https://www.youtube.com/watch?v=cJKtREGhjE8
- https://pushsecurity.com/blog/saas-attack-techniques/


## General Summary
The video discusses the evolving landscape of cyber threats in the context of Software as a Service (SaaS) applications. The presenter, Luke Jennings, highlights the shift from traditional endpoint compromises to attacks targeting cloud identities and SaaS applications. He introduces the concept of a new SaaS cyber kill chain, emphasizing the importance of understanding this new attack paradigm.

## Outline
Introduction

Brief about the presenter: Luke Jennings, VP of Research and Development at Push Security.
Motivation for the research: Understanding attacks in a world where endpoint compromises are less prevalent and SaaS is dominant.
Historical Context

Evolution of cyber threats:
2000s: Traditional perimeter hacking with port scanners, bone scanners, etc.
2010s: Endpoint becomes the new perimeter with phishing, malicious file attachments, and lateral movement.
2020s: Cloud identities become the new perimeter.
Drivers of Shifts in Attacks

Improved security controls: Introduction of firewalls, VPNs, EDR, XDR, etc.
Technological shifts: Emergence of web applications, Wi-Fi, remote working, and SaaS-native organizations.
SaaS Adoption

Definition of SaaS in the context of the video.
Impact of the pandemic on accelerating SaaS adoption.
Differentiation between hybrid SaaS companies and SaaS-native startups.
Infrastructure Perspective

Traditional infrastructure with internal networks, DMZs, and VPNs.
Modern SaaS-native infrastructure with hardened laptops connecting directly to SaaS services.
Kill Chain Phases

Comparison of traditional kill chain phases with the new SaaS cyber kill chain.
Notable changes: Command and control phase becomes less relevant, and execution phase shifts focus.
Reconnaissance Phase

Traditional recon: Port scanning, user enumeration, etc.
SaaS-native recon: SaaS discovery, cloud identity enumeration, SSO enumeration.
Techniques like SAML enumeration and slug/tenant enumeration.
Initial Access

Traditional initial access: Focused on endpoint compromises.
SaaS-native initial access: Targets cloud identities and SaaS applications.
(Note: The transcript ends here, and the video seems to continue discussing the initial access phase and possibly other phases of the SaaS cyber kill chain.)

## Slides
Title Slide:
Title: Understanding the New SaaS Cyber Kill Chain
Subtitle: The evolving landscape of cyber threats in the SaaS era.

Historical Context:
Title: Evolution of Cyber Threats
2000s: Traditional perimeter hacking.
Subtechnique: Port scanners, bone scanners.
Explanation: Tools used to identify open ports and vulnerabilities in the network.
2010s: Endpoint becomes the new perimeter.
Subtechnique: Phishing, malicious file attachments, lateral movement.
Explanation: Techniques focused on compromising individual devices to gain access to the broader network.
2020s: Cloud identities as the new perimeter.
Subtechnique: SaaS-native attacks.
Explanation: Attacks targeting cloud-based identities and services.

Drivers of Shifts in Attacks:
Title: What Drives Attack Evolution?
Improved Security Controls:
Subtechnique: Firewalls, VPNs, EDR, XDR.
Explanation: Security measures introduced to counteract known threats.
Technological Shifts:
Subtechnique: Web applications, Wi-Fi, remote working.
Explanation: New technologies that introduced fresh attack surfaces.

SaaS Adoption:
Title: The Rise of SaaS
Graph/Chart: Showing the increase in SaaS adoption over the years.
Hybrid vs. SaaS-native: Differentiating between companies with mixed infrastructures and those fully on SaaS.

Infrastructure Perspective:
Title: Infrastructure Evolution
Traditional:
Subtechnique: Internal networks, DMZs, VPNs.
Explanation: Older infrastructure model with defined perimeters.
SaaS-native:
Subtechnique: Hardened laptops, direct SaaS connections.
Explanation: Modern infrastructure with devices connecting directly to cloud services.

Kill Chain Phases:
Title: Comparing Kill Chain Phases
Traditional vs. SaaS-native: Table comparing the phases in both models.
Notable Changes: Highlighting the diminishing relevance of command and control, and the shift in the execution phase.

Reconnaissance Phase:
Title: Recon in the SaaS Era
Traditional Recon:
Subtechnique: Port scanning, user enumeration.
Explanation: Identifying network vulnerabilities and potential targets.
SaaS-native Recon:
Subtechnique: SaaS discovery, cloud identity enumeration, SSO enumeration.
Explanation: Finding used SaaS applications, identifying cloud identities, and understanding SSO configurations.

Initial Access:
Title: Gaining the First Foothold
Traditional Access:
Subtechnique: Endpoint compromises.
Explanation: Techniques targeting individual devices.
SaaS-native Access:
Subtechnique: Targeting cloud identities and SaaS applications.
Explanation: Methods to compromise cloud-based services and identities.

Lateral Movement Phase:
Title: Lateral Movement in the SaaS-native World
Traditional: Moving between infrastructure components.
SaaS-native: Moving from one SaaS application to another or between cloud identities.
Link Backdooring: Exploiting trust in internal systems by backdooring links.
Account Recovery: Exploiting the account recovery process (details not provided).
Integration Abuse: Exploiting existing integrations between SaaS applications.

Key Takeaways:
Title: Key Insights from the Webinar
Hybrid SaaS World: The blend of traditional and SaaS applications in enterprises.
SaaS-Oriented Attack Techniques: Emphasis on techniques that don't require endpoint compromises.
Persistence in SaaS: Understanding how persistence works in the SaaS space.
SaaS Attack Matrix: A tool for understanding and simulating SaaS-related attacks.

Conclusion:
Title: Wrapping Up
Thank You: Appreciation for the viewers.
Further Resources: Encouragement to check the website and the SaaS Attack Matrix on GitHub.