#!/usr/bin/python
## ###
#  IP: GHIDRA
# 
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#  
#       http://www.apache.org/licenses/LICENSE-2.0
#  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
##

import re
import os
import sys
import glob
import argparse

class tpp:

    def __init__(self, fname):
        self.data = {'name':'', 'ifdef':'', 'main':'', 'body':'', 'num':''}
        self.info = []
        self.c_file = None
        self.line_num = 0
        self.fname = fname

    def c_write(self, line):
        if not self.c_file: self.c_write(line)
        else: self.c_file.write(line + '\n')

    def test_hdr(self, line):
        self.c_write(line);

    def test_test(self, name):
        self.data['name'] = name

    def test_if(self, line):
        if self.data['name']: self.test_body(line)
        elif self.data['ifdef']:
            sys.stderr.write('ERROR: nested ifdef not allowed in file %s at line %d\n' % (self.fname, self.line_num))
            sys.exit(1);
        else: self.data['ifdef'] = line.strip()

    def test_endif(self, line):
        if self.data['name']: self.test_body(line)

    def test_open_brace(self):
        self.data['body'] = ''

    def test_main(self, main):
        self.data['main'] = main
        self.c_write('''
extern void %(main)s(TestInfo*);
#define %(main)s_NUMB 0
static const char %(main)s_NAME [] = "%(main)s";
''' % self.data)
        self.data['name'] = ''
        self.data['ifdef'] = ''
        self.data['body'] = ''
        self.data['num'] = ''

    def test_close_brace(self):
        if not self.data['name']: return
        self.c_write('')
        if self.data['ifdef']: self.c_write(self.data['ifdef'])
        self.data['num'] = str(len(re.findall(r'^\s+ASSERT', self.data['body'], flags=re.MULTILINE)))
        self.c_write('''#define %(name)s_NUMB %(num)s
static const char %(name)s_NAME [] = "%(name)s";
static void %(name)s()
{
	noteTestMain(__FILE__, __LINE__, %(name)s_NAME);
	{
%(body)s\t}
	breakOnSubDone(__FILE__, __LINE__, %(name)s_NAME);
}''' % self.data)

        if self.data['ifdef']: self.c_write('#endif /* %(ifdef)s */\n' % self.data)
        self.info += [(self.data['name'], self.data['ifdef'])]

        # clear this test
        self.data['name'] = ''
        self.data['ifdef'] = ''
        self.data['body'] = ''

    def test_body(self, line):
        if self.data['name']:
            # add an indentation
            if line[0] == '\t': line = '\t' + line
            self.data['body'] += line
        else:
            self.c_write(line)

    def test_fi(self):
        self.c_write('static FunctionInfo fi[] = {')

        if self.data['main']: self.c_write('\t{ %(main)s_NAME, (testFuncPtr) &%(main)s, %(main)s_NUMB },' % self.data)

        for (e, f) in self.info:
            if f: self.c_write(f)
            self.c_write('\t{ %s_NAME, (testFuncPtr) &%s, %s_NUMB },' % (e, e, e))
            if f: self.c_write('#endif /* %s */' % f)

        self.c_write('\t{ 0, 0, 0 }')
        self.c_write('};')

# This is boilerplate, supplying the main, etc

    def test_boilerplate(self):
        self.c_write('''
static GroupInfo Info = {
	{\'a\', \'B\', \'c\', \'D\', \'e\', \'f\', \'G\', \'h\'},
	fi
};

/* Function exists to make sure that the GroupInfo structure does not
 * get optimized away.
 **/

GroupInfo *%(main)s_Force() {
	return &Info;
}

void %(main)s(TestInfo* not_used) {
	i4 i = 0;
	int numTest = 0;

	TestInfo_reset();

	for (i = 1; Info.funcTable[i].name; i++) Info.funcTable[i].func();

	breakOnDone(__FILE__, __LINE__, %(main)s_NAME);
}''' % self.data)

    def match(self, rexp, line):
        self.m = re.match(rexp, line)
        return self.m

    # parse the test file

    def parse(self):

        if not self.fname.endswith('.test'):
            sys.stderr.write('ERROR: filename %s must end with .test\n' % self.fname)
            sys.exit(1);

        self.c_file = open(re.sub('[.]test', '.c', self.fname), "w")

        self.line_num = 0
        for line in open(self.fname):
            self.line_num += 1
            if self.match(r'TEST\s+(\w*).*', line):
                self.test_test(self.m.group(1))
            elif self.match(r'(?:#include)\s+.*', line):
                self.test_hdr(line)
            elif self.match(r'(?:#if|#ifdef)\s+.*', line):
                self.test_if(line)
            elif self.match(r'#endif.*', line):
                self.test_endif(line)
            elif self.match(r'{\s*(.*)', line):
                self.test_open_brace()
            elif self.match(r'MAIN\s+(\w*).*', line):
                self.test_main(self.m.group(1))
            elif self.match(r'}.*', line):
                self.test_close_brace()
            else:
                self.test_body(line)

        self.test_fi()
        self.test_boilerplate()
        self.c_file.close()
        self.c_file = False

    # the ENTRY function will contain a call to all of the MAIN
    # functions found in .test files in the current directory

    def create_entry(self):
        if os.path.exists(self.fname):
            sys.stderr.write('WARNING: entry filename %s exists\n' % self.fname)
            return;

        extern_lines = []
        main_lines = []
        for tname in glob.glob(re.sub(r'[^/]*$', '*.test', self.fname)):
            with open(tname) as tfile:
                for line in tfile:
                    if self.match(r'MAIN\s+(\w*).*', line):
                        extern_lines.append('\textern void %s(TestInfo* not_used);' % self.m.group(1))
                        main_lines.append('\t%s(&info);' % self.m.group(1))
        self.c_file = open(self.fname, "w")
        self.c_write('#include "pcode_test.h"')
        self.c_write('')
        #for l in extern_lines:
        #    self.c_write(l)
        self.c_write('void main(void) {')
        self.c_write('\tTestInfo info;')
        #for l in main_lines:
        #    self.c_write(l)
        self.c_write('#ifdef BUILD_EXE')
        self.c_write('\texit(0);')
        self.c_write('#endif')
        self.c_write('}')
        self.c_file.close()
        self.c_file = False


parser = argparse.ArgumentParser(description='Precompile test file',
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('test_file', nargs='*', help='Test file to preprocess, must end with .test')
parser.add_argument('--entry', default='', help='Create file ENTRY contianing a main function that calls all MAIN functions')

sys.argv.pop(0)
args = parser.parse_args(sys.argv)

if args.test_file:
    for test_file in args.test_file:
        tpp(test_file).parse()

if args.entry:
    tpp(args.entry).create_entry()

