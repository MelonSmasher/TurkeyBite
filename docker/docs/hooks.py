"""Tables the documentation site makes from the code when it is built.

A page asks for one with a marker on a line of its own, such as
<!-- tb:taxonomy -->. The taxonomy, the console's built-in rules, the shipped
list sources and both command lines each live in exactly one file, which is
read here, so the site always says what the code it was built with does. The
command lines are read as source rather than imported, since their
dependencies are not in the docs image. A marker this does not know, or a
source it cannot read, fails the build.
"""

import ast
import base64
import hashlib
import importlib.util
import inspect
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKER = re.compile(r'^<!-- tb:([a-z-]+) -->$', re.MULTILINE)

TYPES = {'threshold': 'Threshold', 'cardinality': 'Distinct values', 'ratio': 'Ratio',
         'spike': 'Spike', 'new_value': 'First seen', 'absence': 'Silence'}


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _escape(text):
    """Text as Markdown shows it, rather than reading <prefix> as a tag."""
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _cell(text):
    return _escape(text).replace('|', '\\|').replace('\n', ' ')


def _prose(text):
    """A docstring as Markdown: escaped, except its indented examples, which are code."""
    return '\n'.join(line if line.startswith('    ') else _escape(line) for line in text.split('\n'))


def taxonomy():
    module = _module('tb_taxonomy', 'src/libtb/taxonomy/__init__.py')
    rows = ['| Category | Purpose | Service | Risk | Severity |', '|---|---|---|---|---|']
    for category in sorted(module.TAXONOMY):
        facets = {module.PURPOSE: [], module.SERVICE: [], module.RISK: []}
        for facet, path in module.TAXONOMY[category]:
            facets[facet].append(path)
        severity = ', '.join(sorted({module.SEVERITY[p] for p in facets[module.RISK]
                                     if p in module.SEVERITY}))
        rows.append(f'| `{category}` | ' + ' | '.join(
            ', '.join(f'`{p}`' for p in facets[f]) or '' for f in
            (module.PURPOSE, module.SERVICE, module.RISK)) + f' | {severity} |')
    return '\n'.join(rows)


def rules():
    module = _module('tb_rule_defaults', 'console/backend/tbconsole/analysis/defaults.py')
    rows = ['| Rule | Type | Severity | On at install | Looks for |', '|---|---|---|---|---|']
    for rule in module.DEFAULT_RULES:
        rows.append(f'| **{_cell(rule["name"])}** | {TYPES.get(rule["type"], rule["type"])} | '
                    f'{rule["severity"].title()} | {"yes" if rule["enabled"] else "no"} | '
                    f'{_cell(rule["description"])} |')
    return '\n'.join(rows)


def lists():
    with open(ROOT / 'vols/lists/host_files.example.json', encoding='utf-8') as handle:
        sources = json.load(handle)
    rows = ['| List | Categories | Publisher | Trust | Covers subdomains | Copies |',
            '|---|---|---|---|---|---|']
    for source in sorted(sources, key=lambda s: (s['categories'][0], s['name'])):
        match = source.get('match', 'exact')
        rows.append(f'| [{_cell(source["name"])}]({source["url"]}) | '
                    f'{", ".join(f"`{c}`" for c in source["categories"])} | '
                    f'{_cell(source.get("publisher", source["name"]))} | '
                    f'{source.get("trust", "medium")} | '
                    f'{"yes" if match == "subtree" else "as the file says"} | '
                    f'{", ".join(source.get("derived_from") or [])} |')
    return '\n'.join(rows)


# What a value in the source that is not a literal, such as a constant's
# name, reads as: nothing worth printing
OPAQUE = object()


def _literal(node):
    """A literal from the source, or OPAQUE where it is not one."""
    try:
        return ast.literal_eval(node)
    except ValueError:
        return OPAQUE


def _call(node, *names):
    """The call's name when it is click.option, sub.add_parser and the like."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in names:
        return node.func.attr
    return None


def _option_row(names, keywords):
    flag = ', '.join(f'`{n}`' for n in names)
    detail = _cell(keywords.get('help', ''))
    extras = []
    if keywords.get('choices'):
        extras.append('one of ' + ', '.join(f'`{c}`' for c in keywords['choices']))
    if 'default' in keywords and not keywords.get('is_flag') and keywords.get('action') != 'store_true':
        if keywords['default'] not in (None, False, '', OPAQUE):
            extras.append(f'default `{keywords["default"]}`')
    if extras:
        detail = (detail + ' ' if detail else '') + '(' + '; '.join(extras) + ')'
    return f'| {flag} | {detail} |'


def pipeline_cli():
    """`turkeybite`'s commands, read from src/turkeybite without importing it."""
    tree = ast.parse((ROOT / 'src/turkeybite').read_text(encoding='utf-8'))
    out = []
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        name, options, arguments = None, [], []
        for dec in fn.decorator_list:
            kind = _call(dec, 'command', 'option', 'argument')
            if kind == 'command':
                name = _literal(dec.args[0])
            elif kind == 'option':
                flags = [a for a in (_literal(arg) for arg in dec.args) if str(a).startswith('-')]
                keywords = {k.arg: _literal(k.value) for k in dec.keywords}
                options.append(_option_row(flags, keywords))
            elif kind == 'argument':
                arguments.append(str(_literal(dec.args[0])).upper())
        if not name:
            continue
        usage = ' '.join(['turkeybite', name] + arguments + (['[options]'] if options else []))
        doc = _prose(inspect.cleandoc(ast.get_docstring(fn) or '').replace('\b\n', ''))
        out.append(f'### `{name}`\n\n```text\n{usage}\n```\n\n{doc}\n')
        if options:
            out.append('| Option | |\n|---|---|\n' + '\n'.join(options) + '\n')
    return '\n'.join(out)


def console_cli():
    """`python -m tbconsole`'s commands, read from its argument parser without importing it."""
    tree = ast.parse((ROOT / 'console/backend/tbconsole/__main__.py').read_text(encoding='utf-8'))
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    # Every command's parser is assigned to the same name in turn, so the
    # statements are read in order, each add_argument going to the parser
    # most recently assigned to its name
    commands, current = {}, {}
    for statement in main.body:
        call = statement.value if isinstance(statement, (ast.Expr, ast.Assign)) else None
        if call is None:
            continue
        if _call(call, 'add_parser'):
            name = _literal(call.args[0])
            keywords = {k.arg: _literal(k.value) for k in call.keywords}
            commands[name] = {'help': keywords.get('help', ''), 'args': []}
            if isinstance(statement, ast.Assign):
                current[statement.targets[0].id] = name
        elif _call(call, 'add_argument') and isinstance(call.func.value, ast.Name) \
                and call.func.value.id in current:
            keywords = {k.arg: _literal(k.value) for k in call.keywords}
            commands[current[call.func.value.id]]['args'].append((_literal(call.args[0]), keywords))
    out = []
    for name, command in commands.items():
        positional = [a.upper() for a, _ in command['args'] if not a.startswith('-')]
        options = [(a, k) for a, k in command['args'] if a.startswith('-')]
        usage = ' '.join(['python -m tbconsole', name] + positional + (['[options]'] if options else []))
        text = command['help']
        out.append(f'### `{name}`\n\n```text\n{usage}\n```\n\n{_escape(text[:1].upper() + text[1:])}.\n')
        for arg, keywords in command['args']:
            if not arg.startswith('-') and keywords.get('choices'):
                out.append(f'`{arg.upper()}` is one of ' + ', '.join(f'`{c}`' for c in keywords['choices']) + '.\n')
        if options:
            out.append('| Option | |\n|---|---|\n' + '\n'.join(_option_row([a], k) for a, k in options) + '\n')
    return '\n'.join(out)


TABLES = {'taxonomy': taxonomy, 'rules': rules, 'lists': lists,
          'pipeline-cli': pipeline_cli, 'console-cli': console_cli}


def on_page_markdown(markdown, page, **kwargs):
    def table(match):
        name = match.group(1)
        if name not in TABLES:
            raise ValueError(f'{page.file.src_path} asks for an unknown table, {name}')
        return TABLES[name]()
    return MARKER.sub(table, markdown)


# The site's Content-Security-Policy, which nginx sends with every page. Its
# scripts are the bundles, which 'self' allows, and a few lines the theme
# writes into each page, which are allowed by their hashes rather than by
# 'unsafe-inline': the site is on the console's own origin, where any other
# inline script could act as whoever is signed in.
POLICY = ("default-src 'self'; script-src 'self' {hashes}; style-src 'self' 'unsafe-inline'; "
          "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; worker-src 'self'; "
          "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
SCRIPT = re.compile(r'<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>', re.S)
HANDLER = re.compile(r'\son[a-z]+\s*=|href\s*=\s*["\']?\s*javascript:', re.I)
RUNNABLE = ('', 'text/javascript', 'module')


def inline_hashes(html):
    """The CSP hashes of the inline scripts a page runs."""
    hashes = set()
    for match in SCRIPT.finditer(html):
        attrs = match.group('attrs')
        if re.search(r'\ssrc\s*=', attrs):
            continue
        kind = re.search(r'type\s*=\s*"([^"]*)"', attrs)
        if (kind.group(1) if kind else '') not in RUNNABLE:
            continue
        digest = hashlib.sha256(match.group('body').encode('utf-8')).digest()
        hashes.add("'sha256-" + base64.b64encode(digest).decode() + "'")
    return hashes


CANONICAL = re.compile(r'\s*<link rel="canonical"[^>]*>')


def on_post_build(config, **kwargs):
    """Writes the policy to TBDOCS_CSP_FILE, for nginx, when the image is built.

    A page with an inline event handler or a javascript: link fails the
    build, since no hash can allow it. The sitemap and each page's canonical
    link go: they would name site_url's host, which is a placeholder, since
    the site is served at each deployment's own address, behind sign-in.
    """
    for name in ('sitemap.xml', 'sitemap.xml.gz'):
        if os.path.exists(os.path.join(config['site_dir'], name)):
            os.remove(os.path.join(config['site_dir'], name))
    hashes = set()
    for folder, _, files in os.walk(config['site_dir']):
        for name in files:
            if not name.endswith('.html'):
                continue
            path = os.path.join(folder, name)
            with open(path, encoding='utf-8') as handle:
                html = handle.read()
            if CANONICAL.search(html):
                html = CANONICAL.sub('', html)
                with open(path, 'w', encoding='utf-8') as handle:
                    handle.write(html)
            if HANDLER.search(SCRIPT.sub('', html)):
                raise ValueError(f'{path} has an inline event handler or a javascript: link, '
                                 f'which the site\'s Content-Security-Policy would block')
            hashes |= inline_hashes(html)
    target = os.environ.get('TBDOCS_CSP_FILE')
    if target:
        with open(target, 'w', encoding='utf-8') as handle:
            handle.write(POLICY.format(hashes=' '.join(sorted(hashes))))
