# Ignorelist

The ignorelist can be used to remove a domain or host from a specific context category.

Building and tuning your ignorelist can help reduce false positives.

In the example below the sites listed will have the `porn` category removed from them.

```json
{
  "porn": [
    "wwdl.net",
    "stun.wwdl.net",
    "dicks.com",
    "www.dicks.com",
    "eonline.com",
    "www.eonline.com",
    "tenor.com",
    "api.tenor.com",
    "media.tenor.com"
  ],
  "malware": [
    "doubleverify.com",
    "tps.doubleverify.com",
    "cdn.doubleverify.com",
    "rtbcdn.doubleverify.com"
  ],
  "malicious": [
    "doubleverify.com",
    "tps.doubleverify.com",
    "cdn.doubleverify.com",
    "rtbcdn.doubleverify.com"
  ]
}
``` 

About the sites listed:

*   wwdl.net - Dedicated hosting solution.
*   stun.wwdl.net - Most likely related to VOIP / SIP.
*   dicks.com & www.dicks.com - Redirects to www.dickssportinggoods.com.
*   eonline.com & www.eonline.com - An American cable television network.
*   tenor.com & api.tenor.com & media.tenor.com - Tenor is an online GIF search engine and database.
*   doubleverify.com - Used for ads but is not likely to be malware.

None of the sites listed above are directly related to porn, though they do each appear on a porn list that TB uses.
To enable the ignorelist copy `ignorelist.example.json` to `ignorelist.json` and the next time domains and hosts are loaded into redis the ignorelist will be processed.
You can also modify `ignorelist.json` to meet your own needs.

## How far an entry reaches

In `index` mode an entry is a correction that is weighed whenever an event is categorised, so it holds however the category arrived: from the host's own list entry, from a parent domain's entry, or from a list that names the whole domain.

*   `example.com` covers `example.com` and `www.example.com`, nothing else.
*   `*.example.com` covers `example.com` and every subdomain of it.

So the three tenor entries above can be written as one, `*.tenor.com`. A suppressed category is still recorded on the event, in `bite.contexts_suppressed`, so you can see a correction taking effect.

In `valkey` mode an entry only edits the host list key with exactly that name, so a category arriving from a parent domain is not removed.

## Using example ignorelist as your ignorelist

I'm maintaining my own ignorelist in `ignorelist.example.json` if you wish to use this as your `ignorelist.json`, symlink it instead of copying it.

If you use `ignorelist.example.json` as your ignorelist **do not modify it** as it's checked into source control and you wont be able to update Turkey Bite.

If you'd like to add to the list submit a merge/pull request.

### Contributing to the ignorelist

*   Fork the project into your personal namespace.
*   Then clone your forked version:

```bash
git clone https://github.com/<username>/TurkeyBite.git
```

*   Make your own development branch:

```bash
git branch <username>/development
```

*   Make your changes.
*   Commit your changes:

```bash
git commit -m 'added example.com to the ignorelist'
```

*   push your changes to your branch

```bash
git push -u origin <username>/development
```

*   Create a merge/pull request into the master branch of the upstream repo.
