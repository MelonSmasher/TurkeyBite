# 3. Why a site has its category

<div class="tb-progress"></div>

Every category comes from a domain list, and every list is wrong about something. TurkeyBite weighs what the lists say before believing them, and every event shows its working. Knowing how to read it tells you how far to trust a finding.

<div class="tb-step" data-step="cat-1" markdown>

### Open an event

<a class="tb-try md-button md-button--primary" href="/explore?q=has%3Acategory">Search for categorised events</a>

Click any row. The panel that opens has three parts: **Who** asked, **What** was asked, and **Why it is categorised this way**.

</div>

<div class="tb-step" data-step="cat-2" markdown>

### Read the evidence

Under **Why it is categorised this way**:

* The coloured chips are the event's **risk**, **purpose** and **service**, the three sides of a category. `expressvpn` says both whose service it is (ExpressVPN) and what risk it carries (a VPN).
* A category with a tick **is believed**: enough independent lists agree, or a list trusted on its own names it. The lists that agree are named below it.
* A category with a question mark **is only a candidate**: a list claimed it, but without the support it needs. It is recorded so you can search for it, and it never raises a finding on its own.
* A crossed-out category **was cancelled by the ignorelist**, your own list of corrections.
* If Quad9 or Cloudflare were asked for a second opinion, their answers are at the bottom.

</div>

<div class="tb-step" data-step="cat-3" markdown>

### Find what the lists only claimed

<a class="tb-try md-button" href="/explore?q=has%3Acandidate%20AND%20NOT%20has%3Acategory">Search for candidates only</a>

`has:candidate AND NOT has:category` finds lookups that some list claimed something about and nothing was believed. Most are harmless: one broad list being broad. A threat candidate on a name nobody else names is worth a second look, and a second opinion from Quad9 and Cloudflare is how TurkeyBite settles most of them; see [A second opinion from resolvers](../categories/resolvers.md).

</div>

<div class="tb-step" data-step="cat-4" markdown>

### See an incidental lookup

<a class="tb-try md-button" href="/explore?q=incidental%3Atrue">Search for incidental lookups</a>

A lookup is not always a choice. A news article with a Facebook pixel makes the browser look up `connect.facebook.net` whether or not the reader uses Facebook. Hosts like that are marked **incidental**: what they say about purpose and service becomes a candidate, so a page with a Like button does not make its reader a Facebook user. A risk stays, since the pixel tracks the reader either way.

</div>

<div class="tb-step" data-step="cat-5" markdown>

### See what nothing names

<a class="tb-try md-button" href="/explore?q=type%3Adns%20AND%20NOT%20has%3Acategory">Search for uncategorised lookups</a>

Plenty of lookups have no category at all, because no list names the domain. The **DNS health** dashboard ranks them in its **Uncategorised domains** table. An administrator can label the busiest of them in a few minutes, which module 7 shows.

</div>

## Check yourself

<div class="tb-quiz" data-answer="3" markdown>

An event shows `malicious` with a question mark, claimed by one list. What does that mean?

1. The site is malicious, and a finding has been raised.
2. The site is safe.
3. One list says so, without the independent support TurkeyBite needs to believe it, so it is recorded and no rule treats it as a threat.
4. The ignorelist cancelled it.

<div class="tb-explain" markdown>
A candidate is a claim held back. It is neither a verdict that the site is safe nor one that it is malicious. Rules read the believed categories, so it raises nothing. If you think it is right, look at the domain's profile, which shows every list behind it.
</div>

</div>

<div class="tb-quiz" data-answer="2" markdown>

Why is `connect.facebook.net` marked incidental?

1. Facebook asked for it to be.
2. Other sites load it, so looking it up does not mean the person chose to use Facebook.
3. It is a tracker, so it carries no risk.

<div class="tb-explain" markdown>
Social plugins, pixels, embedded players and sign-in endpoints are looked up on someone else's behalf. Marking them stops a page's Like button counting as its reader using Facebook. A risk such as tracking stays, because it applies whether or not they use Facebook.
</div>

</div>

**Next:** [4. Triage a finding](4-findings.md)
