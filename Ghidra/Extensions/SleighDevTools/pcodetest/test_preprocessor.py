#!/usr/bin/env python

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

import argparse
import sys
from pathlib import Path
from test_parser import TestParser


def print_err(*args, **kwargs):
    '''
    Print to stderr.
    '''
    print(*args, file=sys.stderr, **kwargs)


def create_test_entry(filepath: Path) -> bool:
    '''
    Create a file in `filepath` that serves as the entry for the tests.
    The entry function will contain a call to all of the main functions found
    in test files in the directory of the output file.
    '''
    if filepath.exists():
        print_err(f'ERROR: entry filename {filepath} exists\n')
        return False
    # Iterate testfiles in the same folder as filepath and collect entry names
    test_entries = []
    for testpath in filepath.parent.glob('*.test'):
        testdata = TestParser(testpath)
        test_entries.append(testdata.get_main_function())
    # Generate the file
    with filepath.open('w') as file:
        file.write('#include "pcode_test.h"\n')
        file.write('\n')
        for t in test_entries:
            file.write(f'extern void {t}(TestInfo* info);\n')
        file.write('\n')
        file.write('void main(void) {\n')
        file.write('    TestInfo info;\n')
        file.write('\n')
        for t in test_entries:
            file.write(f'    {t}(&info);\n')
        file.write('\n')
        file.write('#ifdef BUILD_EXE\n')
        file.write('    exit(0);\n')
        file.write('#endif\n')
        file.write('}\n')
    return True


def _write_test_body_element(outfile, element):
    if element['type'] == 'text':
        outfile.write(element['body'])
        return True
    elif element['type'] == 'test':
        outfile.write(f'\n')
        outfile.write(
            f'#define {element["name"]}_NUMB {element["assert_num"]}\n')
        outfile.write(
            f'static const char {element["name"]}_NAME [] = "{element["name"]}";\n')
        outfile.write(f'static void {element["name"]}()\n')
        outfile.write(f'{{\n')
        outfile.write(
            f'    noteTestMain(__FILE__, __LINE__, {element["name"]}_NAME);\n')
        outfile.write(f'    {{\n')
        outfile.write(f'{element["body"]}')
        outfile.write(f'    }}\n')
        outfile.write(
            f'    breakOnSubDone(__FILE__, __LINE__, {element["name"]}_NAME);\n')
        outfile.write(f'}}\n')
        return True
    elif element['type'] == 'main':
        outfile.write(f'\n')
        outfile.write(f'extern void {element["name"]}(TestInfo*);\n')
        outfile.write(f'#define {element["name"]}_NUMB 0\n')
        outfile.write(
            f'static const char {element["name"]}_NAME [] = "{element["name"]}";\n')
        return True
    elif element['type'] == 'if':
        outfile.write(f'\n')
        outfile.write(element['body'])
        for c in element['children']:
            if not _write_test_body_element(outfile, c):
                return False
        outfile.write(f'#endif\n')
        return True
    else:
        print_err(f'ERROR: Unrecognized tree entry {element} in test!')
        return False


def _write_test_info_table_element(outfile, element):
    if element['type'] == 'test':
        outfile.write(
            f'    {{ {element["name"]}_NAME, (testFuncPtr) &{element["name"]}, {element["name"]}_NUMB }},\n')
        return True
    elif element['type'] == 'if':
        outfile.write(element['body'])
        for el in element['children']:
            _write_test_info_table_element(outfile, el)
        outfile.write(f'#endif\n')
        return True
    return True


def create_test_file(filepath: Path) -> bool:
    '''
    Parse the test file in `filepath` and generate the corresponding
    C source test file.
    '''
    if filepath.suffix != '.test':
        print_err(f'ERROR: filename {filepath} must end with .test\n')
        return False
    testdata = TestParser(filepath)
    with filepath.with_suffix('.c').open('w') as outfile:
        # Write testfile body
        for element in testdata.get_tree():
            if not _write_test_body_element(outfile, element):
                return False

        # Now write the function info
        main = testdata.get_main_function()
        outfile.write(f'\nstatic FunctionInfo fi[] = {{\n')
        outfile.write(
            f'    {{ {main}_NAME, (testFuncPtr) &{main}, {main}_NUMB }},\n')
        for element in testdata.get_tree():
            if not _write_test_info_table_element(outfile, element):
                return False
        outfile.write(f'    {{ 0, 0, 0 }}\n')
        outfile.write(f'}};\n')

        # Now write the boilerplate...
        outfile.write(f'\n')
        outfile.write(f'static GroupInfo Info = {{\n')
        outfile.write(
            f'    {{\'a\', \'B\', \'c\', \'D\', \'e\', \'f\', \'G\', \'h\'}},\n')
        outfile.write(f'    fi\n')
        outfile.write(f'}};\n\n')
        outfile.write(
            f'/* Function exists to make sure that the GroupInfo structure does not\n')
        outfile.write(f' * get optimized away.\n')
        outfile.write(f' **/\n\n')
        outfile.write(f'GroupInfo *{main}_Force() {{\n')
        outfile.write(f'    return &Info;\n')
        outfile.write(f'}}\n\n')
        outfile.write(f'void {main}(TestInfo* not_used) {{\n')
        outfile.write(f'    i4 i = 0;\n')
        outfile.write(f'    int numTest = 0;\n')
        outfile.write(f'    TestInfo_reset();\n')
        outfile.write(f'    for (i = 1; Info.funcTable[i].name; i++)\n')
        outfile.write(f'        Info.funcTable[i].func();\n')
        outfile.write(f'    breakOnDone(__FILE__, __LINE__, {main}_NAME);\n')
        outfile.write(f'}}\n')
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Precompile test file')
    parser.add_argument('--entry', type=Path, default=None,
                        help='Create a main entry file contianing calls all test functions')
    parser.add_argument('test_file', type=Path, default=None, nargs='*',
                        help='Test file to preprocess, must end with .test')
    args = parser.parse_args()

    if (args.test_file is None or len(args.test_file) == 0) and args.entry is None:
        parser.print_help()
        sys.exit(1)

    print(args.test_file)

    if args.test_file is not None:
        for test_file in args.test_file:
            if not create_test_file(test_file):
                sys.exit(1)

    if args.entry is not None:
        if not create_test_entry(args.entry):
            sys.exit(1)
