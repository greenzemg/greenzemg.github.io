---
layout: post
title: Enhancing Security with Sentinel Queries:- Real-World Use Cases
date: 2024-04-25 10:14:00-0400
description: In this blog post, I will be discussing various query rules and hunting queries that can be used by SOC analysts to detect and investigate security incidents using Microsoft Sentinel.
tags: soc, microsoft, sentinel, KQL
categories: security
giscus_comments: true
related_posts: false
toc:
    sidebar: left
---

Microsoft Sentinel is a cloud-based SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) solution designed to detect, investigate, respond to, and hunt threats across enterprise infrastructures and products. Under the hood, it is an ocean of logs collected from various network devices and applications, ingested through data connectors and enhanced by machine learning, KQL (Kusto Query Language—a custom query language), and analytics, to name a few.

In this blog post, I provide Kusto queries for various real world use cases to stay fit your organizational security posture. From identifying unauthorized access attempts to monitoring network traffic and detecting malicious activities, these queries will help you proactively secure your environment.

In case you are new to Sentinel, I recommend checking out the [official documentation](https://docs.microsoft.com/en-us/azure/sentinel/overview) and the following [youtube video](https://www.youtube.com/watch?v=xMj7a4Ns_cU) to get started.

Success!!

## Detecting Access from the Tor Network

**Description**:
Adversaries often use the VPN and Tor network to hide and anonymize their activities, making it challenging to trace their origin. They sometimes use Tor to access internal resources, exfiltrate data, or conduct brute force authentication attempts. This query can detect and alert on any login attempts from Tor browsers. To implement this, you'll need to create a watchlist of known Tor exit nodes and upload it to Sentinel. You can find a list of Tor exit nodes [here](https://check.torproject.org/exit-addresses) or [here](https://github.com/SecOps-Institute/Tor-IP-Addresses).

**Query**:

```javascript
// Retrieve list of Tor exit nodes IPs from the watchlist
let watchlist = (_GetWatchlist('TorExitNodes') | project TorIPAddress);
// SigninLogs from the past 5 minutes
SigninLogs
| where TimeGenerated > ago(5m)
// Check if the IPAddress from SigninLogs is in the watchlist
| where IPAddress in (watchlist)
| project TimeGenerated, IPAddress
```

**Test**:
To trigger this alert, anyone can use a Tor browser and attempt to log in to https://portal.azure.com.

## Detecting Logins from Blacklisted IPs

**Description**: If a certain IP address has been used in the past for attack in the past, there is a high probability that a later successful login from that IP address is malicious. This rule detects logins from any of the black list of IPs that has previously been compiled by a system administrator.

**Query**:

```javascript
let blacklistIPs = _GetWatchlist('blacklistOfIps') | project ip;
// Load the list of list blacklisted IPs
SigninLogs
| where ResultType == 0
// Only successful logins
| where IPAddress in (blacklistIPs)
// IP address matches blacklisted IPs
| project TimeGenerated, IPAddress, AccountDisplayName
```

**Test**: To test this rule and to trigger the alert, use a VPN to switch to a known bad IP and then log in.

## Detecting Communication with a C&C Server

Command and Control (C&C) servers, as it names speak, are launching pad for cyber criminals used to communicate with compromised systems, often to exfiltrate data or send malicious commands. This query checks for any incoming successful communication from a known blacklisted C&C IP. An external data source is used to create the blacklist of C&C server IPs. Identifying such communications can help in detecting and mitigating ongoing attacks.

**Query**:

```javascript
let BlockList =
    (externaldata(ip:string)
    [@"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    ]
    with(format="csv")
    | where ip matches regex "(^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    | distinct ip
);
SigninLogs
| sort by TimeGenerated
| where IPAddress in (BlockList) or IPAddress == "85.145.247.7"
// Add specific IP for testing
| where ResultType == 0
// Only successful logins
| project TimeGenerated, OperationName, Identity, IPAddress, DeviceDetail

```

**Test**: To test this rule, add your IP to the list of known C&C server IPs and attempt a login.

## How to Deal With Account Enumeration Attacks

An adversary can use account enumeration attacks to identify valid usernames and password.
This query targets a tactic commonly used by adversaries: account detection attacks leveraging Brute Force (T1087) from the MITRE ATT&CK framework;For more information follow this [link](https://attack.mitre.org/techniques/T1087/). It identifies a surge in login attempts from a single IP targeting multiple user accounts, a potential sign of brute-forcing valid accounts.

**Query**:

```javascript
let BorderValue = 3;
SigninLogs
| distinct UserDisplayName, IPAddress
| summarize AmountOfAccounts = count(), Adresses = make_list(UserDisplayName, 100) by IPAddress
| where AmountOfAccounts >= BorderValue
```
