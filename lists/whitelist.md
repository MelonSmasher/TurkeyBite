# Whitelist

The whitelist can be used to remove a domain or host from a specific context category.

Building and tuning your whitelist can help reduce false positives.

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
To enable the whitelist copy `whitelist.example.json` to `whitelist.json` and the next time domains and hosts are loaded into redis the whitelist will be processed.
You can also modify `whitelist.json` to meet your own needs.

## Using example whitelist as your whitelist

I'm maintaining my own whitelist in `whitelist.example.json` if you wish to use this as your `whitelist.json`, symlink it instead of copying it.

If you use `whitelist.example.json` as your whitelist **do not modify it** as it's checked into source control and you wont be able to update Turkey Bite.

If you'd like to add to the list submit a merge/pull request.

### Contributing to the whitelist

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
git commit -m 'added example.com to the whitelist'
```

*   push your changes to your branch

```bash
git push -u origin <username>/development
```

*   Create a merge/pull request into the master branch of the upstream repo.
