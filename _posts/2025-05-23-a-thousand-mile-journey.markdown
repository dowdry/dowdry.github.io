---
layout: post
title: A thousand mile journey
date: 2025-05-22 16:05:00 +1000
img: software.jpg # Add image post (optional)
tags: [Development, Entitlements] # add tag
---
*A little history about me before we start: I have been involved in SOCs for the majority of my career in Cyber Security. In 2023 I was provided with an OffSec Unlimited Subscription (1-year of access to unlimited courses & content) which enabled me to complete the OSCP, OSWP and OSDA trainings and examinations. With a couple of months left of my subscription, I decided to undertake the OffSec macOS Researcher (OSMR) certification as Apple expertise was in short supply within our SOC.*

*Completing the OSMR certification led me to many resources; most notably the Objective-See tools developed by Patrick Wardle, and later attending my first Objective-by-the-Sea conference in Maui, as well as a handful of CVEs awarded through the Apple Security Bounty program.*

---

I have been toying with the idea of leveraging the Endpoint Security framework to supercharge my otherwise cumbersome and, honestly, clumsy approach to bug hunting on macOS. While there are many tools already publicly available to help with this -- Red Canary Mac Monitor (Brandon Dalton), ESFPlayground (Jaron Bradley / The Mitten Mac), ProcessMontor & File Montor (Objective-See), and even eslogger (Apple) -- I decided to go down the path of developing my own application.

There does exist a barrier for entry however, and in this case I would need to be granted with the `com.apple.developer.endpoint-security.client` entitlement by Apple. Of course I could grant this to myself by disabling specific macOS security mechanisms (namely SIP and AMFI), but as my intention was to "discover" potential vulnerabilities while using my daily driver Mac this was not an option.

I was a little apprehensive about requesting this entitlement without even a single line of code yet written, and even more unsure after reading Patrick Wardle's thoughts on the matter in **The Art of Mac Malware: Volume II - Chapter 11**:
> 	"Given the power of Endpoint Security, Apple is understandably cautious
	about granting requests for the client entitlement, even to renowned secu-
	rity companies. That said, you can take several measures to improve your
	chances of receiving one. First, register as a company, such as an LLC or
	equivalent. I’m aware of only one instance in which Apple granted the
	Endpoint Security client entitlement to an individual. Second, in your
	request, make sure to describe exactly what you plan to do with the entitle-
	ment. The Endpoint Security client entitlement is designed for security
	tools, so include details of the tool you’re developing and articulate exactly
	why it needs the use of Endpoint Security."

After submitting my request detailing the above intentions, as well as citing Apple's own Monitoring System Events with Endpoint Security [sample code](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security) under "Company / Product URL", I was assigned the entitlement for Endpoint Security. Perhaps I caught an Apple employee on a good day, or was simply just lucky. Regardless, after a couple of weeks I received notification that I was granted this entitlement.

![Twitter](assets/img/01x1.png)

And with that single step, my journey has started.