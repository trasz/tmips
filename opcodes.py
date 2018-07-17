#!/usr/bin/env python3

import pprint
import sys

if len(sys.argv) != 3:
    sys.exit('usage: %s opcodes-path header-path' % sys.argv[0])

infile = open(sys.argv[1], 'r')

outfile = open(sys.argv[2], 'w')
include_name = sys.argv[2].upper().replace('.', '_')
print('/* generated by %s; contains only the opcodes with defined 14..12 and 6..0 */' % sys.argv[0], file=outfile)
print('\n#ifndef %s\n#define %s\n' % (include_name, include_name), file=outfile)

for line in infile:
    line = line.split('#', 1)[0].strip()
    fields = line.split()
    if not fields:
        continue

    opcode = fields[0].upper().replace('.', '')

    tmp = {}
    for field in fields:
        if field.find('=') == -1:
            continue
        field = field.split('=', 1)
        if field[1] == 'ignore':
            continue
        tmp[field[0]] = int(field[1], 0)

    if '1..0' not in tmp:
        print('%s: opcode %s missing 1..0; ignoring' % (sys.argv[0], opcode), file=sys.stderr)
        continue
    if '6..2' not in tmp:
        print('%s: opcode %s missing 6..2; ignoring' % (sys.argv[0], opcode), file=sys.stderr)
        continue
    if '14..12' not in tmp:
        print('%s: opcode %s missing 14..12; ignoring' % (sys.argv[0], opcode), file=sys.stderr)
        continue

    value = tmp['1..0'] | tmp['6..2'] << 2 | tmp['14..12'] << 12
    print('#define\tOP_%-5s\t%#010x' % (opcode, value), file=outfile)

print('\n#endif /* !%s */' % include_name, file=outfile)
