#!/usr/bin/env python3
"""The docs link the other documents they name, and every relative link works.

Usage: md-links.py ROOT [--fix]

In each section of each Markdown file (from one heading to the next), the first
mention of another document in the repository must be a link to it: `X.md` as a
whole inline code span, a bare X.md, or the document's name alone (SETUP, README,
...). Later mentions in the same section stay plain. Fenced code, other inline
code and existing links are left alone. With --fix, each unlinked first mention
becomes a relative link, to the section's anchor when a quoted section name of
the target follows it (`STORES.md`, "Approving a connection").

Every relative link to a .md file must name a file that exists and, with a #, a
heading in it. Without --fix, prints each problem and exits 1 if there are any.
"""
import os
import re
import sys

# CHANGELOG.md: history, and its sections become the release notes.
# SKILL.md: its installed copy has no siblings, and it says to use nothing beside it.
SKIP_FILES = {'CHANGELOG.md', 'SKILL.md'}
SKIP_DIRS = {'.git', '.claude', 'node_modules'}
# A document named without ".md" ("SETUP step 3", "README's threat model").
STEMS = re.compile(
    r'(?<![\w./\[-])(README|SETUP|ROTATION|STORES|DESIGN|CONTRIBUTING|STORE-TEST'
    r'|INSTALL-linux-macos|INSTALL-windows|INSTALL-options)(?![\w-]|\.\w)')
LINK = re.compile(r'!?\[(?:[^\]\\]|\\.)*\]\([^)]*\)')
BARE = re.compile(r'(?<![\w/.`-])([A-Za-z0-9_][A-Za-z0-9_./-]*\.md)(?![\w/`-])')
CODE_NAME = re.compile(r'`([A-Za-z0-9_./-]+\.md)`')
SECTION = re.compile(r'(?:\'s|’s)?,?\s+[“"]([^”"]{1,80})[”"]')
MARK = re.compile('\0([^\0]*)\0([^\0]*)\0')
# "a `SECURITY.md`", "its SETUP.md": any folder's file of that name, not one file.
GENERIC = re.compile(r'(?:\b(?:a|an|its|their|each|every|that folder\'s|a folder\'s)\s+)$', re.IGNORECASE)


def slug(heading):
    """GitHub's anchor for a heading."""
    s = re.sub(r'[^\w\- ]', '', heading.strip().lower())
    return s.replace(' ', '-')


def headings(path):
    out = set()
    seen = {}
    fence = False
    with open(path, encoding='utf-8') as f:
        for line in f:
            if line.lstrip().startswith('```'):
                fence = not fence
                continue
            m = None if fence else re.match(r'#{1,6}\s+(.*?)\s*#*\s*$', line)
            if m:
                s = slug(m.group(1).replace('`', ''))
                n = seen.get(s, 0)
                seen[s] = n + 1
                out.add(s if n == 0 else f'{s}-{n}')
    return out


def all_docs(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            if f.endswith('.md'):
                yield os.path.relpath(os.path.join(d, f), root)


def resolve(root, doc, name):
    """The repo path a mention of name in doc means, or None."""
    here = os.path.dirname(doc)
    while True:
        cand = os.path.normpath(os.path.join(here, name))
        if os.path.isfile(os.path.join(root, cand)):
            return cand
        if not here:
            return None
        here = os.path.dirname(here)


def check_links(root, doc, lineno, line, linked, problems):
    for m in LINK.finditer(line):
        t = re.search(r'\]\(([^)\s]*)', m.group(0)).group(1)
        if re.match(r'[a-z]+:', t):
            continue
        if t.startswith('#'):
            tgt, anc = doc, t[1:]
        else:
            p, _, anc = t.partition('#')
            if not p.endswith('.md'):
                continue
            tgt = os.path.normpath(os.path.join(os.path.dirname(doc), p))
        linked.add(tgt)
        if not os.path.isfile(os.path.join(root, tgt)):
            problems.append(f'{doc}:{lineno}: link to missing {t}')
        elif anc and anc not in headings(os.path.join(root, tgt)):
            problems.append(f'{doc}:{lineno}: no heading #{anc} in {tgt}')


def mark_mentions(root, doc, lineno, text, problems):
    """Text with each mention of another document wrapped as \\0label\\0target\\0.

    Left alone: a name after "a", "its", "each" and the like (any folder's file of
    that name), and anything inside straight double quotes (a quoted pointer or
    message, as it is written elsewhere)."""
    def marker(label, name, before):
        if GENERIC.search(before):
            return None
        tgt = resolve(root, doc, name)
        if tgt and tgt != os.path.normpath(doc):
            return '\0' + label + '\0' + tgt + '\0'
        return None

    def stem(m):   # a name that resolves to this file itself is left alone
        return marker(m.group(1), m.group(1) + '.md', m.string[:m.start()]) or m.group(0)

    def prose(t):
        t = BARE.sub(lambda m: marker(m.group(1), m.group(1), m.string[:m.start()]) or m.group(0), t)
        parts = re.split('(\0[^\0]*\0[^\0]*\0)', t)
        return ''.join(p if p.startswith('\0') else STEMS.sub(stem, p) for p in parts)

    out = ''
    for i, chunk in enumerate(re.split(r'("[^"\n]*")', text)):
        if i % 2:              # a quoted string: as it is
            out += chunk
            continue
        pos = 0
        for cm in re.finditer(r'`[^`]*`', chunk):   # inline code: only a whole file name
            out += prose(chunk[pos:cm.start()])
            name = CODE_NAME.fullmatch(cm.group(0))
            out += (name and marker(cm.group(0), name.group(1), chunk[:cm.start()])) or cm.group(0)
            pos = cm.end()
        out += prose(chunk[pos:])
    return out


def process(root, doc, fix):
    path = os.path.join(root, doc)
    with open(path, encoding='utf-8') as f:
        text = f.read()
    out = []
    problems = []
    fence = False
    linked = set()   # documents already linked in this section
    comment = False  # inside an HTML comment
    for lineno, line in enumerate(text.split('\n'), 1):
        if line.lstrip().startswith('```'):
            fence = not fence
        if fence or line.lstrip().startswith('```'):
            out.append(line)
            continue
        heading = re.match(r'#{1,6}\s', line)
        if heading:
            linked = set()
        check_links(root, doc, lineno, line, linked, problems)
        # Left as written: headings, quoted prompts meant for pasting (> ...),
        # HTML comments (to their closing -->), and lines with reference-style links.
        was_comment = comment
        if '<!--' in line:
            comment = True
        if comment and '-->' in line[line.find('<!--') + 4 if '<!--' in line else 0:]:
            comment = False
        if heading or was_comment or '<!--' in line or line.lstrip().startswith('>') \
                or re.search(r'\]\[|^\s*\[[^\]]+\]:', line):
            out.append(line)
            continue
        new = ''
        pos = 0
        for lm in list(LINK.finditer(line)) + [None]:
            end = lm.start() if lm else len(line)
            buf = mark_mentions(root, doc, lineno, line[pos:end], problems)

            def link(m, buf=buf, linked=linked, lineno=lineno):
                label, tgt = m.group(1), m.group(2)
                if tgt in linked:
                    return label
                linked.add(tgt)
                anc = ''
                sm = SECTION.match(buf[m.end():])
                if sm:
                    want = slug(sm.group(1))
                    hits = sorted(h for h in headings(os.path.join(root, tgt))
                                  if h == want or h.startswith(want + '-'))
                    if want in hits or len(hits) == 1:
                        anc = '#' + (want if want in hits else hits[0])
                problems.append(f'{doc}:{lineno}: unlinked {label}')
                return f'[{label}]({os.path.relpath(tgt, os.path.dirname(doc) or ".")}{anc})'

            new += MARK.sub(link, buf)
            if lm:
                new += lm.group(0)
                pos = lm.end()
        out.append(new)
    if fix and '\n'.join(out) != text:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(out))
    return problems


def main():
    root = sys.argv[1]
    fix = '--fix' in sys.argv
    problems = []
    for doc in sorted(all_docs(root)):
        if os.path.basename(doc) not in SKIP_FILES:
            problems += process(root, doc, fix)
    for p in problems:
        print(p)
    if problems and not fix:
        sys.exit(1)


if __name__ == '__main__':
    main()
