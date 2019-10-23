# TurkeyBite

## What is TurkeyBite?

A domain and host context analysis pipeline.

TurkeyBite analyzes DNS query packets to glean some context into each request. TB allows you to identify clients who are requesting domains associated with anything from porn to gambling to shopping and everything in between.

### Whats under the hood?

TurkeyBite relies on the following technologies

* Python3
* Redis
* Bind9
* Packetbeat
* Elasticsearch
* Kibana
* Domain and host lists from many sources

In practice the analysis pipeline looks like this:

![flow-chart](img/flow.png)

### What DNS servers does this work with?

As of right now I have tested this with a Microsoft DNS server and I am running this in production with multiple Bind9 servers. Since Packetbeat is used to grab and send packets to Redis this should work with any DNS server that can also run Packetbeat.

### Will this block clients?

Short answer: no.

Long answer: TB is an analysis tool not a DNS based blocking tool. For something like that check out [pi-hole](https://pi-hole.net/). In theory there is no reason why you couldn't run both pi-hole and TB in tandem. TB is designed to be as unobtrusive as possible so that it's implementation impact is never felt by clients.

## Setup

WIP - coming soon
