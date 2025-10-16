
from tqdm.auto import tqdm
from subprocess import CalledProcessError

import syzgrapher

TESTS = [
    ('Resource hierearchy', '''
r0 = make_hA()
r1 = make_hB()
r2 = make_hC()
use_hP(r0, r1, r2)
use_hA(r0)
use_hB(r1)
use_hC(r2)
    '''),
    ('Inout', '''
r0 = make_x()
inout_x(&AUTO=<r1=>r0)
use_x(r0)
use_x(r1)
    '''),
    ('Deletion', '''
r0 = make_x()
r1 = make_y()
use_both(r0, r1)
del_x(r0)
    ''')
]

for name, prog in TESTS:
    prog = prog.strip()

    unique = set()
    for i in tqdm(range(500), desc=name):
        try:
            res = syzgrapher.mutate('test', 'syzgrapher', prog, i, verbose=False)
        except CalledProcessError as e:
            print('Err on', i)
            try:
                syzgrapher.mutate('test', 'syzgrapher', prog, i, verbose=True)
            except CalledProcessError as e2:
                print(e2.stdout.decode('latin-1'))
                print(e2.stderr.decode('latin-1'))
            exit(0)

        unique.add(res)

    for u in unique:
        print(u)
        print('---')
