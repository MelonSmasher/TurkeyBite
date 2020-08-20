# Bind9 Config

Below is an example my my Bind9 configs. You need to change these for your environment! This example uses Windows DNS master servers. You'll also need to configure your master DNS servers to allow zone transfers to this new slave DNS server.

**Important** do not forward DNS requests to the DNS servers you plan on capturing packets from! This could be really really bad for your DNS servers. In the example below we forward DNS requests to internet DNS servers. This is the safest option, and likely the fastest option. If your local zones don't have the record, you're likely looking up another domain anyway.

`/etc/bind/named.conf`

```conf
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";
```
---

`/etc/bind/named.conf.local`

```conf
include "/etc/bind/slave.conf";
```

---

`/etc/bind/named.conf.default-zones`

```conf
// prime the server with knowledge of the root servers
zone "." {
        type hint;
        file "/etc/bind/db.root";
};

// be authoritative for the localhost forward and reverse zones, and for
// broadcast zones as per RFC 1912

zone "localhost" {
        type master;
        file "/etc/bind/db.local";
};

zone "127.in-addr.arpa" {
        type master;
        file "/etc/bind/db.127";
};

zone "0.in-addr.arpa" {
        type master;
        file "/etc/bind/db.0";
};

zone "255.in-addr.arpa" {
        type master;
        file "/etc/bind/db.255";
};
```

---

`/etc/bind/slave.conf`

```conf
acl "adservers" {
    10.10.10.20;
    10.10.10.21;
};
masters ad-masters {
    10.10.10.20;
    10.10.10.21;
};

// Example domain zone
zone "MYDOMAIN.COM" {
    type slave;
    masters { 
        ad-masters;
    };
    file "/var/cache/bind/mydomain.com";
    allow-transfer { 
        "adservers";
     };
    allow-notify { 
        "adservers";
     };
};

// Example of subdoamin
zone "subdomain.mydomain.com" {
    type slave;
    masters { 
        ad-masters;
    };
    file "/var/cache/bind/subdomain.mydomain.com";
    allow-transfer { 
        "adservers";
     };
    allow-notify { 
        "adservers";
     };
};

// _msdcs subdomain for Windows DNS
zone "_msdcs.mydomain.com" {
    type slave;
    masters { 
        ad-masters;
     };
    file "/var/cache/bind/msdcs.mydomain.com";
    allow-transfer { 
        "adservers";
     };
    allow-notify { 
        "adservers";
     };
};

// Example reverse lookup zone
zone "10.in-addr.arpa" {
    type slave;
    masters { 
        ad-masters;
     };
    file "/var/cache/bind/10.in-addr.arpa";
    allow-transfer { 
        "adservers";
     };
    allow-notify { 
        "adservers";
     };
};
```

You'll want to setup zones for your subdomains and reverse lookup zones. This will be unique to your environment.

---

`/etc/bind/named.conf.options`

```conf
options {
    directory "/var/cache/bind";
    check-names master warn; // Must be WARN only for AD/Windows
    max-udp-size 4096;
    dnssec-enable yes; //optional
    dnssec-validation yes; // optional, can be yes or no
    dnssec-lookaside auto; // MUST be auto for AD/Windows
    forwarders {
        1.1.1.1; // CF Main
        1.0.0.1; // CF Alt
        208.67.222.222; // Open DNS
        208.67.220.220; // Open DNS Alt
        8.8.8.8; // Google Main
        8.8.4.4; // Google Alt
    };
    auth-nxdomain no;    # conform to RFC1035
    listen-on-v6 { any; };
    allow-recursion { any; };
    allow-query { any; };
    allow-query-cache { any; };
};
```