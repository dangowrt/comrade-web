#!/usr/bin/env python3
"""Redact IPs, tokens, user/host from an asciicast v2 (.cast) recording.

Usage:
  ./redact_cast.py in.cast > out.cast
  ./redact_cast.py in.cast -o out.cast --user alice --host thinkpad \
      --extra secret.example.com --token-min-len 16

A .cast is newline-delimited JSON: line 1 is the header object, the rest are
[time, code, data] events. Visible terminal text is the JSON-escaped `data` of
"o" (output) events, so this parses JSON per line (never regexes the raw file)
and rewrites only `data`, leaving timing byte-for-byte.

Exit status is non-zero if a sensitive pattern survives ONLY because it was
split across two output events (a value can straddle write() boundaries). Fix
by re-recording with placeholders, or hand-edit the offending line. Best
practice: record with fake data to begin with; this script is the safety net.
"""
import argparse, json, os, re, socket, sys

RE_IPV4 = re.compile(
    r'(?<![\d.])'
    r'(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    r'(?![\d.])'
)

_H = r'[0-9A-Fa-f]{1,4}'
RE_IPV6 = re.compile(
    r'(?<![0-9A-Fa-f:.])(?:'
    rf'(?:{_H}:){{7}}{_H}|'
    rf'(?:{_H}:){{1,7}}:|'
    rf'(?:{_H}:){{1,6}}:{_H}|'
    rf'(?:{_H}:){{1,5}}(?::{_H}){{1,2}}|'
    rf'(?:{_H}:){{1,4}}(?::{_H}){{1,3}}|'
    rf'(?:{_H}:){{1,3}}(?::{_H}){{1,4}}|'
    rf'(?:{_H}:){{1,2}}(?::{_H}){{1,5}}|'
    rf'{_H}:(?::{_H}){{1,6}}|'
    rf'::(?:ffff(?::0{{1,4}})?:)?'
    r'(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r')(?![0-9A-Fa-f:.])'
)

def plausible_ipv6(m):
    return m.count(':') >= 2 and re.search(r'[0-9A-Fa-f]', m) is not None

DEFAULT_TOKEN_RE = r'\b[1-9A-HJ-NP-Za-km-z]{%d,}\b'


class Redactor:
    def __init__(self, args):
        self.literals = []
        user = args.user if args.user is not None else os.environ.get('USER')
        host = args.host if args.host is not None else socket.gethostname()
        if user and not args.no_user:
            self.literals.append((re.compile(r'\b' + re.escape(user) + r'\b'), '[user]'))
        if host:
            short = host.split('.')[0]
            for h in {host, short}:
                if h:
                    self.literals.append((re.compile(r'\b' + re.escape(h) + r'\b'), '[host]'))
        for extra in args.extra:
            self.literals.append((re.compile(re.escape(extra)), '[redacted]'))
        tok = args.token_regex or (DEFAULT_TOKEN_RE % args.token_min_len)
        self.re_token = re.compile(tok)
        self.ipv4_repl = args.ipv4_repl
        self.ipv6_repl = args.ipv6_repl
        self.token_repl = args.token_repl

    def scrub(self, s):
        for rx, repl in self.literals:
            s = rx.sub(repl, s)
        s = RE_IPV4.sub(self.ipv4_repl, s)
        s = RE_IPV6.sub(lambda m: self.ipv6_repl if plausible_ipv6(m.group(0))
                        else m.group(0), s)
        s = self.re_token.sub(self.token_repl, s)
        return s


def main():
    p = argparse.ArgumentParser()
    p.add_argument('infile')
    p.add_argument('-o', '--outfile')
    p.add_argument('--user', help='literal username to redact (default $USER)')
    p.add_argument('--no-user', action='store_true')
    p.add_argument('--host', help='literal hostname (default socket.gethostname())')
    p.add_argument('--extra', action='append', default=[],
                   help='extra literal string to redact (repeatable)')
    p.add_argument('--token-regex', help='override token pattern')
    p.add_argument('--token-min-len', type=int, default=16)
    p.add_argument('--ipv4-repl', default='203.0.113.0')
    p.add_argument('--ipv6-repl', default='2001:db8::')
    p.add_argument('--token-repl', default='[token]')
    p.add_argument('--codes', default='o,i,m',
                   help='event codes whose data is scrubbed')
    args = p.parse_args()

    r = Redactor(args)
    codes = set(args.codes.split(','))
    out = open(args.outfile, 'w', encoding='utf-8') if args.outfile else sys.stdout

    concat = []
    leaks = 0
    with open(args.infile, encoding='utf-8') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line.strip():
                out.write('\n')
                continue
            obj = json.loads(line)
            if isinstance(obj, dict):
                if 'title' in obj:
                    obj['title'] = r.scrub(obj['title'])
                if isinstance(obj.get('env'), dict):
                    obj['env'] = {k: r.scrub(v) if isinstance(v, str) else v
                                  for k, v in obj['env'].items()}
            elif isinstance(obj, list) and len(obj) == 3:
                _t, code, data = obj
                if code in codes and isinstance(data, str):
                    obj[2] = r.scrub(data)
                    if code == 'o':
                        concat.append(obj[2])
            out.write(json.dumps(obj, ensure_ascii=False,
                                 separators=(',', ':')) + '\n')

    joined = ''.join(concat)
    for name, rx, flt in (('IPv4', RE_IPV4, None),
                          ('IPv6', RE_IPV6, plausible_ipv6),
                          ('token', r.re_token, None)):
        for m in rx.finditer(joined):
            if flt and not flt(m.group(0)):
                continue
            leaks += 1
            sys.stderr.write(f'WARNING: possible {name} leak split across '
                             f'events: {m.group(0)!r}\n')
    if args.outfile:
        out.close()
    if leaks:
        sys.stderr.write(f'{leaks} residual pattern(s) survived -- '
                         f're-record with placeholders or hand-edit.\n')
        sys.exit(2)


if __name__ == '__main__':
    main()
