# People behind phones (RADIUS)



A DNS lookup carries only the address that asked. A phone's reverse DNS
name is whatever the phone called itself, so every iPhone is `iphone`, and
findings pile hundreds of people onto that one name. On 802.1X Wi-Fi, NPS
knows who signed in on each device and which address it was given. Send
NPS's log to TurkeyBite, and each DNS lookup records the person who held
its address at the time as `bite.client_user`, and the device as
`bite.client_mac`. Findings and profiles then name the person.

On every NPS server, open the NPS console, go to **Accounting → Change Log
File Properties**, and:

-   on **Settings**, tick *Accounting requests*, *Authentication requests*
    and *Periodic accounting status*;
-   on **Log File**, choose **DTS Compliant**, and a new file **Daily**.

The access points must send accounting with interim updates. Check that:

-   the log's accounting lines carry `Framed-IP-Address` and `Class`;
-   its Access-Accept lines carry `SAM-Account-Name` and `Class`.

The name a device gives, `User-Name`, is its outer identity. For many
profiles that is `anonymous`, and anyone can set it to someone else's name.
The account NPS actually authenticated is in the Access-Accept, and the
session's `Class` ties the two together. That is why authentication
requests are logged too.

-   **When it has seen the Access-Accept,** TurkeyBite uses that account, and
    once a session has it, no name the device gives replaces it. The name
    holds only under that sign-in's `Class`. A laptop whose user logs off and
    whose machine account then signs in, under a new `Class`, is no longer
    that person's. Each sign-in keeps its own name from when its
    Access-Accept was logged, so a lookup handled late, after a backlog,
    gets the name in force at its time.
-   **When it has not,** the session is held by someone unnamed, since the
    name the device gives could be anyone's. Its lookups get the device's MAC
    address but no user, and it still counts as the address's holder, so the
    previous holder is not credited with them. A later interim update names
    it once the Access-Accept has been seen. Set `trust_given_names: true` to
    name such sessions by the device's own word instead, if it is a person's.
-   **When accounting lines carry no `Class`,** no session can be tied to its
    sign-in, and the workers say so in their log.

Then install [Filebeat](https://www.elastic.co/beats/filebeat) on each
server. It sends the lines to their own Valkey list, `<redis.channel>:nps`,
and needs to reach Valkey, as Packetbeat does:

```yaml
# filebeat.yml on each NPS server. Comment out output.elasticsearch,
# which the Windows package turns on: Filebeat takes one output.
filebeat.inputs:
  - type: filestream
    id: nps-accounting
    paths:
      # NPS's default; use the directory set on the Log File tab
      - 'C:\Windows\System32\LogFiles\IN*.log'
    # Accounting requests and Access-Accepts only
    include_lines: ['<Packet-Type data_type="0">[24]</Packet-Type>']
    # Not the days before Filebeat started
    ignore_older: 24h

output.redis:
  hosts: ["valkey.domain.com:6379"]
  password: "your_valkey_password"
  db: 0                              # the same as redis.db in config.yaml
  key: "turkeybite:nps"              # <redis.channel>:nps
  datatype: "list"
```

Then turn it on in `config.yaml`, in every worker at once:

-   `timezone` is the time zone the NPS servers log in. It has no default,
    because a wrong one dates every line hours out. A line dated after
    Filebeat read it is not recorded, and the workers' log says to check
    the zone.
-   `realms` lists your own realm and NetBIOS domain, so that
    `jsmith@example.edu` and `EXAMPLE\jsmith` are recorded as `jsmith`, as
    Browserbeat names people.

```yaml
processor:
  radius:
    enable: true
    timezone: America/New_York
    realms: [example.edu, example]
```

Restart the librarian on this version before turning it on. It maps
`bite.client_mac` in the indices that already exist, and an index that has
mapped it as text would break every profile spanning that day.

Each worker takes what waits on the list before each batch of DNS events.
It keeps each address's sessions in Valkey, in the queue's database, for a
day after the last report. Who held an address is asked of Valkey for
every lookup, so a stop recorded by one worker counts in all of them at
once. Only that nobody held an address is remembered, for `cache_sec` (5
seconds), so a lookup that soon after another worker records the
address's first session can miss it. The
lines themselves are not indexed, and the workers' log names no one.

-   **A worker with `radius` off** leaves the lines to workers that have it
    on. It only keeps the list to its newest 10,000 lines, so the list cannot
    grow without end while nobody takes them.
-   **Lines that arrive on the DNS queue instead,** from a Filebeat sent to
    the wrong key, are dropped, and the workers' log says where to send
    them.

-   **How long an address counts as a person's.** A session holds its address
    from its start until it stops. While it has not stopped, it holds it
    until `grace_sec` (20 minutes) after an access point last reported it.
    Keep that above the access points' interim interval.
-   **After a stop.** The address is nobody's from the moment of a stop,
    because DHCP may give it to another device. A lookup credited to nobody
    is better than one credited to the wrong person.
    -   A stop counts even when it names nobody, or gives no address.
    -   A device reported with a new address leaves its old one, unless it
        is reported with the old one again.
-   **Reported, or only inferred.** Between its first and last reports with
    the address, a session's hold on it is reported. Before, from its start,
    and after, through `grace_sec`, it is only inferred. A session reported
    with the address at the time wins over one whose hold is only
    inferred.
-   **Roaming.** A phone that roams to another access point stops one session
    and starts another, often before the new one reports an address. A
    session that starts without one, within two minutes of its device last
    being reported, takes the address the device had then. It doesn't if
    another device has been reported with that address since.
-   **Two sessions at once.** A session that took its address on roaming
    loses it to another device reported with the address after its own
    device last was. Otherwise, when two sessions cover a lookup, the one
    that started later wins.
-   **What it cannot do.**
    -   Lookups a device makes on joining, before an access point first reports
        its address, have no user.
    -   Lookups over IPv6 have none, since NPS reports IPv4 addresses.
    -   Lines are taken at most once: those in hand when a worker dies are
        lost, until the next interim update.
-   **Who can claim an address.** Anyone who can write to Valkey can claim an
    address for anyone, as they can already write events.
