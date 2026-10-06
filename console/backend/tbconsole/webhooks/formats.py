"""What a delivery looks like on the wire, for each kind of receiver.

Every delivery starts as the same canonical event, which is what the generic
JSON format sends as it is and what the signature covers. Chat formats turn
it into a message their service renders: Slack's blocks, a Microsoft Teams
Adaptive Card, a Discord embed, a Google Chat card.
"""

SEVERITY_COLOURS = {'critical': '#d92d20', 'high': '#f04438', 'medium': '#f79009',
                    'low': '#2e90fa', 'info': '#667085'}
SEVERITY_EMOJI = {'critical': ':rotating_light:', 'high': ':red_circle:',
                  'medium': ':large_orange_circle:', 'low': ':large_blue_circle:',
                  'info': ':white_circle:'}

FORMATS = {
    'json': 'Generic JSON, signed',
    'slack': 'Slack incoming webhook',
    'teams': 'Microsoft Teams workflow (Adaptive Card)',
    'discord': 'Discord webhook',
    'google_chat': 'Google Chat webhook',
}

EVENTS = {
    'finding.created': 'A rule raised a new finding',
    'finding.reminder': 'An open finding is still matching, after the rule\'s re-alert gap',
    'finding.status_changed': 'Someone changed a finding\'s status or assignee',
    'rule.failing': 'A rule has failed three runs in a row',
    'test': 'A test delivery sent from the console',
}


def _slack(text: str, limit: int) -> str:
    """Text for Slack mrkdwn: its three control characters escaped, as Slack
    asks, so a value from the events cannot become a link, and cut to fit."""
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _plain(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _markup(text: str, limit: int) -> str:
    """Text for Google Chat, whose cards read HTML and whose messages turn
    <users/all> into a mention and <url|text> into a link."""
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return _plain(text, limit)


def _markdown(text: str, limit: int) -> str:
    """Text for a Teams card, whose markdown makes [text](url) a link."""
    for ch in '\\[]()*_`':
        text = text.replace(ch, '\\' + ch)
    return _plain(text, limit)


def _discord(text: str, limit: int) -> str:
    """Text for a Discord embed, with no masked links."""
    return _plain(text.replace('[', '\\[').replace(']', '\\]'), limit)


def _headline(event: dict) -> str:
    finding = event.get('finding') or {}
    kind = event.get('event', '')
    if kind == 'test':
        return 'Test delivery from TurkeyBite Console'
    if kind == 'rule.failing':
        rule = event.get('rule') or {}
        return f'Rule failing: {rule.get("name", "?")}'
    prefix = {'finding.created': 'New finding', 'finding.reminder': 'Still happening',
              'finding.status_changed': 'Finding updated'}.get(kind, 'Finding')
    return f'{prefix}: {finding.get("title", "")}'


def _facts(event: dict) -> list[tuple[str, str]]:
    finding = event.get('finding') or {}
    if not finding:
        rule = event.get('rule') or {}
        facts = []
        if rule.get('last_error'):
            facts.append(('Error', str(rule['last_error'])[:300]))
        return facts
    facts = [('Severity', str(finding.get('severity', '')).title()),
             ('Status', str(finding.get('status', '')).replace('_', ' ').title()),
             ('Rule', str(finding.get('rule_name', '')))]
    if finding.get('entity'):
        facts.append(('Entity', str(finding['entity'])))
    facts.append(('Events', f'{finding.get("event_count", 0):,}'))
    if finding.get('top_domains'):
        facts.append(('Top domains', ', '.join(d['key'] for d in finding['top_domains'][:3])))
    return facts


def render(fmt: str, event: dict) -> dict:
    """The JSON body to POST for this receiver."""
    if fmt == 'json':
        return event
    finding = event.get('finding') or {}
    severity = finding.get('severity', 'info') if finding else 'info'
    headline = _headline(event)
    summary = finding.get('summary') or event.get('message') or ''
    link = event.get('url')
    facts = _facts(event)

    if fmt == 'slack':
        # Slack's limits: 150 characters in a header, 3,000 in a section's
        # text, 2,000 in each field
        blocks = [
            {'type': 'header', 'text': {'type': 'plain_text', 'text': _plain(headline, 150)}},
        ]
        if summary:
            blocks.append({'type': 'section', 'text': {'type': 'mrkdwn', 'text': (
                f'{SEVERITY_EMOJI.get(severity, "")} {_slack(summary, 2900)}')}})
        if facts:
            blocks.append({'type': 'section', 'fields': [
                {'type': 'mrkdwn', 'text': f'*{k}*\n{_slack(v, 1900)}'} for k, v in facts[:10]]})
        if link:
            blocks.append({'type': 'actions', 'elements': [
                {'type': 'button', 'text': {'type': 'plain_text', 'text': 'Open in console'},
                 'url': link}]})
        # In an attachment, so Slack draws the severity colour beside it
        return {'text': _slack(headline, 2900), 'attachments': [
            {'color': SEVERITY_COLOURS.get(severity, '#667085'), 'blocks': blocks}]}

    if fmt == 'teams':
        body = [
            {'type': 'TextBlock', 'text': _markdown(headline, 300), 'weight': 'Bolder', 'size': 'Medium',
             'wrap': True, 'color': 'Attention' if severity in ('critical', 'high') else 'Default'},
        ]
        if summary:
            body.append({'type': 'TextBlock', 'text': _markdown(summary, 2000), 'wrap': True})
        if facts:
            body.append({'type': 'FactSet', 'facts': [{'title': k, 'value': _markdown(v, 500)}
                                                      for k, v in facts[:12]]})
        card = {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                'type': 'AdaptiveCard', 'version': '1.4', 'body': body}
        if link:
            card['actions'] = [{'type': 'Action.OpenUrl', 'title': 'Open in console', 'url': link}]
        return {'type': 'message', 'attachments': [
            {'contentType': 'application/vnd.microsoft.card.adaptive', 'content': card}]}

    if fmt == 'discord':
        colour = int(SEVERITY_COLOURS.get(severity, '#667085').lstrip('#'), 16)
        embed = {'title': _plain(headline, 256), 'description': _discord(summary, 2000),
                 'color': colour,
                 'fields': [{'name': k, 'value': _discord(v, 1024) or '-', 'inline': True}
                            for k, v in facts[:25]]}
        if link:
            embed['url'] = link
        # A value from the events must never ping @everyone
        return {'username': 'TurkeyBite', 'embeds': [embed], 'allowed_mentions': {'parse': []}}

    if fmt == 'google_chat':
        widgets = [{'decoratedText': {'topLabel': k, 'text': _markup(v, 500)}} for k, v in facts[:12]]
        if summary:
            widgets.insert(0, {'textParagraph': {'text': _markup(summary, 2000)}})
        if link:
            widgets.append({'buttonList': {'buttons': [
                {'text': 'Open in console', 'onClick': {'openLink': {'url': link}}}]}})
        return {'text': _markup(headline, 1000), 'cardsV2': [{'cardId': 'finding', 'card': {
            'header': {'title': _plain(headline, 200), 'subtitle': f'Severity: {severity}'},
            'sections': [{'widgets': widgets}]}}]}

    raise ValueError(f'unknown webhook format {fmt!r}')
