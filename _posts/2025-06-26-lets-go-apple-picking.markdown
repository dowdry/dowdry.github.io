---
layout: post
title: Let's go apple picking- Scaling macOS bug discovery
date: 2025-06-26 12:21:00 +1000
img: checklist.jpg
tags: [EndpointSecurity, Entitlements, Elastic, Bounty, Vulnerability, Exploitation] # add tag
---
Conducting macOS security research at scale is hard. Useful telemetry is firmly restricted to entitled applications, and taking ad-hoc approaches to interrogate system binaries involves disabling OS protections, potentially tainting observable events.

### Background

A comment from [Gergely Kalman](https://www.youtube.com/watch?v=WIR_Vue7eC0), one of the first macOS security bloggers I was ever to, often comes to mind; ["Do dumb analysis, but do it at scale"](https://gergelykalman.com/lateralus-CVE-2023-32407-a-macos-tcc-bypass.html).

My first macOS vulnerabilities were the product of technical write-ups and blog posts. I would read + replicate the attacks and then attempt to introduce novel ways to circumvent the described fix. Rarely did I identify a vulnerable component of macOS based solely on my own observations and research.

As it turns out, from time-to-time researchers whom I admire also find inspiration from their peers.

![image](/assets/img/image1.gif)

With a desire to contribute something of my own to the community, I began this project.

### The Idea

To get serious about scaling my analysis, I need telemetry. A serious amount of it. 

But why stop there? What about Apple's opaque web of elaborately named binary entitlements, which support their auth model? You can Google hundreds of unique binary entitlements with barely a single page of results detailing its relevance, meaning or impact to security (if any).

Therefore, I decided to contextualise that stream of system data with other sources; binary entitlements and launch constraints came to mind. Enriching this data, as well as running correlation rules across it at a regular cadence (much like _any_ EDR tool, but for the detection of potential macOS platform logic bugs), will be necessary. I wanted untainted, **and** unmuted system data, especially.

The best source of telemetry is undoubtedly Endpoint Security (ES). Introduced in 2019 to replace the Kauth KPI, the unsupported MAC kernel framework, and the OpenBSM audit trail, ES has evolved to supply **104** distinct NOTIFY events (as at macOS 26 beta 2).

However, there exists a barrier to entry: the coveted `com.apple.developer.endpoint-security.client` entitlement.

> *"Given the power of Endpoint Security, Apple is understandably cautious about granting requests for the client entitlement, even to renowned security companies. That said, you can take several measures to improve your chances of receiving one. First, register as a company, such as an LLC or equivalent. I’m aware of only one instance in which Apple granted the Endpoint Security client entitlement to an individual."* 

~ **Patrick Wardle, The Art of Mac Malware - Volume II: Detection**

There are several community tools available that assist those of us ("the un-entitled") who are interested in plundering ES for its insights:
- Objective-See / Patrick Wardle: Process, and File Monitor
- Brandon Dalton: Red Canary Mac Monitor
- TheMittenMac / Jaron Bradley: ESFPlayground

These have been created for different objectives, and as such the number and types of ES_EVENTS that they are subscribed to align to their primary purpose and the derived value of those EVENT sources:

| Tool    | ES Event Coverage |
| -------- | ------- |
| Process, and File Monitor | 10    |
| Red Canary Mac Monitor    | 41    |
| ESFPlayground | 51     |

While I could self-prescribe the ES client entitlement on a device with SIP and AMFI disabled, I want to avoid that scenario for a few distinct reasons:
- My telemetry is being produced by my daily-driver Mac,
- Obtaining the best and most realistic data set involves leveraging an array of applications and services on macOS, many of which require authentication (I don't log into iCloud within my VMs),
- Some enhanced Apple services are simply not available within an un-registered VM (E.g., Apple Intelligence), and
- Generally, disabling OS level protections is a bad idea.

There is a time and place for `lldb` and `dtrace`, but it is not here.

It occurred to me that the above requirements can be overcome, and a simple low-rent solution is available: `/usr/bin/eslogger`.

Apple's `eslogger` is the bundled ES interface for macOS. It allows for user-specified event subscriptions to take place and logs all events to standard output in a handy JSON format. While its man page suggests that it must not be considered a stable or reliable source for interfacing with the ES API a thorough review has proven it to be quite comprehensive with its output. Regarding stability? Well, it hasn't failed me yet.

But does `eslogger` output represent all data structures defined in the Endpoint Security header files? Yes.

Does `eslogger` implement all modifications / new additions to Endpoint Security at each release? A review of macOS 26 beta's enhancements shows that they are in fact supported immediately (no surprise.)

![image](/assets/img/image2.png)

![image](/assets/img/image3.png)

Finally, `eslogger` leverages the API functions for packed environmental variables and file descriptors as they relate to _ES_EVENT_TYPE_NOTIFY_EXEC_, process all audit_tokens and present time values in an ISO 8601 compatible format. This will assist when we eventually consume it into the Elastic stack.

So, I took output from `eslogger` and leveraged `jq`, the command-line JSON processor, and parsed only fields relevant to my research and normalise it using [ECS](https://www.elastic.co/docs/reference/ecs). This data can be enriched from an array of other sources by way of a Logstash Enrichment Pipeline. As a test case, I chose binary entitlements.

![image](/assets/img/image4.png)

### Proof of Concept ###

To establish a proof of concept, I decided to consume a baseline number of ES events which would be most relevant for macOS logic bugs resulting in common bug classes: TCC and SIP bypass, local priv escalation, and sandbox escapes.

| Event    | Description |
| -------- | ------- |
| **ES_EVENT_TYPE_NOTIFY_EXEC** | An identifier for a process that notifies endpoint security that it is executing an image |
| **ES_EVENT_TYPE_NOTIFY_FORK** | An identifier for a process that notifies endpoint security that it is forking another process |
| **ES_EVENT_TYPE_NOTIFY_CREATE** | An identifier for a process that notifies endpoint security that it is creating a file |
| **ES_EVENT_TYPE_NOTIFY_OPEN** | An identifier for a process that notifies endpoint security that it is opening a file |
| **ES_EVENT_TYPE_NOTIFY_WRITE** | An identifier for a process that notifies endpoint security that it is deleting a file |
| **ES_EVENT_TYPE_NOTIFY_RENAME** | An identifier for a process that notifies endpoint security that it is renaming a file |
| **ES_EVENT_TYPE_NOTIFY_UNLINK** | An identifier for a process that notifies endpoint security that it is deleting a file |

As an aside, I cannot overstate the value of manually detailing ES EVENT message structures and mapping them to the Elastic Common Schema (ECS). For example, clearly distinguishing between the process (pre-execve(2)) and target (post-exec image) structs in ES_EVENT_TYPE_NOTIFY_EXEC, which represent different states of the same PID, was crucial for accurate context alignment and understanding es_message_t semantics.

Behold. Spreadsheets!

![image](/assets/img/image5.png)

For data enrichment, a simple bash script designed to run `codesign` across all executable macOS binaries, filtering for a pre-defined list of entitlements (E.g., "com.apple.private.tcc.allow", "com.apple.private.tcc.manager.access.delete", "com.apple.rootless.install", and any "-heritable" counterparts). Once again `jq` was used to format this output in JSON pairing the "process.executable" with the relevant entitlement(s) nested with either boolean, array or string values.

Logstash consumed the output with ease.

![image](/assets/img/image6.png)

Once ingested into Logstash, this "entitlement" index became the base for my ingest pipeline associated with ES event data, which results in all *es_process_t *_Nonnull process* data having associated binary entitlements attached and stored into our "eslogger" index.

![image](/assets/img/image7.png)

The data is flowing in, and while familiarising myself with EQL and ES\|QL I run a few spot checks to ensure process lineage and binary context are what is to be expected.

![image](/assets/img/image8.png)

I was certain that to get a broad spectrum of telemetry I would have to become the greatest Apple fanboy imaginable. 

>_Goodbye 1Password, hello Passwords._
>
>_Goodbye Spotify, hello Apple Music._
>
>_Goodbye human intelligence, hello Apple Intelligence._

The data is rolling in, and I gain familiarity with EQL and EQ\|QL queries - both in an effort to confirm the fidelity of the data but also to familiarise myself with the nuances of each query language. I did not expect my first finding, a SIP bypass, to come from this early data validation stage. Simple logic comparable to "show me all process binaries with SIP privileges that wrote to non-protected system locations"? One symlink is all it took.

In my next blog post, I will be discussing CVE-2025-43191; which Apple plans to patch in macOS Sequoia 15.6, and then hopefully many more.

For now REAP: refine - enrich - add - process.

### My Sincere Thanks ###

This post forms not only part of a series of posts on this topic, but also supports my application to speak at OBTS v8.0 in October.

I would like to thank the following people who assisted me from early concept to POC in many **many** DMs, Signal Messages, and Zoom calls. In order of most swear words:

- **Gergely Kalman** (@gergely_kalman) for many hours on Zoom, so many cool ideas, and many fruitful discoveries
- **Colson Wilhoit** (@DefSecSentinel) for an exceptional walkthrough of ELK, Elastic modules / visualisations, and Endpoint Security
- **Csaba Fitzl** (@theevilbit) for so much knowledge validation and careful direction
- **Brandon Dalton** (@PartyD0lphin) for keen insights into Mac Monitor, and Endpoint Security