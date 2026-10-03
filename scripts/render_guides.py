#!/usr/bin/env python3
"""Render the portable public guide into GitHub-readable Markdown."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()

for language, filename in [('en', 'how-to.md'), ('ro', 'how-to.ro.md')]:
    guide = json.loads((ROOT / f'docs/guide.{language}.json').read_text())
    lines = [f"# {guide['title']}", '', guide['intro'], '',
             '[English](how-to.md) · [Română](how-to.ro.md)', '',
             f"Release: `{guide['version']}`", '']
    lines += [f"- [{section['title']}](#{section['id']})" for section in guide['sections']]
    for section in guide['sections']:
        lines += ['', f'<a id="{section["id"]}"></a>', '', f"## {section['title']}", '']
        for block in section['blocks']:
            kind = block['type']
            if kind == 'paragraph':
                lines += [block['text'], '']
            elif kind == 'list':
                lines += [f"{i}. {item}" for i, item in enumerate(block['items'], 1)] + ['']
            elif kind == 'code':
                lines += [f"```{block['language']}", block['code'], '```', '']
            elif kind == 'table':
                def row(values):
                    return '| ' + ' | '.join(value.replace('|', r'\|') for value in values) + ' |'
                lines += [row(block['headers']), row(['---'] * len(block['headers']))]
                lines += [row(values) for values in block['rows']] + ['']
            elif kind == 'links':
                lines += [f"- [{link['label']}]({link['href']})" for link in block['links']] + ['']
            else:
                raise ValueError(f'Unknown guide block: {kind}')
    rendered = '\n'.join(lines).rstrip() + '\n'
    output = ROOT / 'docs' / filename
    if args.check:
        if not output.exists() or output.read_text() != rendered:
            raise SystemExit(f'{filename} is stale; run python3 scripts/render_guides.py')
    else:
        output.write_text(rendered)
