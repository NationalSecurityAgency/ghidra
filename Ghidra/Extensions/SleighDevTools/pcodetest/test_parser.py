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

import re
from pathlib import Path


class _TestfileReader:
    def __init__(self, path: Path):
        '''
        This class reads a file while keeping count of the file number.
        '''
        self._path = path
        self._file = None
        self._curr_line = None

    def open(self):
        if self._file is None:
            self._file = self._path.open('r')
            self._curr_line = 0

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None
            self._curr_line = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def peekline(self):
        pos = self._file.tell()
        line = self._file.readline()
        self._file.seek(pos)
        return line

    def readline(self) -> str:
        line = self._file.readline()
        self._curr_line += 1
        return line

    def current_line(self) -> int:
        return self._curr_line

    def file_path(self) -> str:
        return str(self._path)


class _TokenMatcher:
    # Token enumeration
    TOKEN_UNKNOWN = 0
    TOKEN_INCLUDE = 1
    TOKEN_IF_START = 2
    TOKEN_IF_END = 3
    TOKEN_TEST_FCN = 4
    TOKEN_MAIN_FCN = 5
    TOKEN_BODY_START = 6
    TOKEN_BODY_END = 7
    TOKEN_EMPTY = 8
    TOKEN_TEXT = 9
    TOKEN_ASSERT = 10

    # Regex matchers
    _MATCHERS = [
        (TOKEN_INCLUDE, re.compile(r'(?:#include)\s+.*')),
        (TOKEN_IF_START, re.compile(r'(?:#if|#ifdef)\s+.*')),
        (TOKEN_IF_END, re.compile(r'#endif.*')),
        (TOKEN_TEST_FCN, re.compile(r'TEST\s+(\w*).*')),
        (TOKEN_MAIN_FCN, re.compile(r'MAIN\s+(\w*).*')),
        (TOKEN_BODY_START, re.compile(r'{\s*(.*)')),
        (TOKEN_BODY_END, re.compile(r'}.*')),
        (TOKEN_EMPTY, re.compile(r'^\s*$')),
        (TOKEN_ASSERT, re.compile(r'^\s+ASSERT')),
        (TOKEN_TEXT, re.compile(r'.*')),
    ]

    def match(self, string: str):
        '''
        Returns a tuple with a matched token and possible token parameters.
        '''
        for token, matcher in self._MATCHERS:
            res = matcher.match(string)
            if res:
                return token, list(res.groups())
        return self.TOKEN_UNKNOWN, []

    def peek_token(self, file):
        while line := file.peekline():
            token, params = self.match(line)
            return (token, params, line)
        return (None, None, None)

    def get_token(self, file):
        while line := file.readline():
            token, params = self.match(line)
            if token == self.TOKEN_EMPTY:
                continue
            return (token, params, line)
        return (None, None, None)


class TestParser:
    def __init__(self, path: Path):
        '''
        Parse `.test` files.
        '''
        self._tree = []
        self._parse(path)

    def _raise_syntax_error(self, file, msg, line):
        raise SyntaxError(
            msg, (file.file_path(), file.current_line(), 0, line))

    def _parse(self, path: Path):
        with _TestfileReader(path) as file:
            tokenizer = _TokenMatcher()
            self._parse_root(file, tokenizer)

    def _parse_root(self, file, tokenizer):
        while True:
            element = self._parse_element(file, tokenizer)
            if element is None:
                return
            self._tree.append(element)

    def _parse_element(self, file, tokenizer):
        token, params, line = tokenizer.get_token(file)
        if token is None:
            return None
        elif token == tokenizer.TOKEN_INCLUDE or \
                token == tokenizer.TOKEN_TEXT:
            return {'type': 'text', 'body': line}
        elif token == tokenizer.TOKEN_IF_START:
            children = self._parse_if_children(file, tokenizer)
            return {'type': 'if', 'body': line, 'children': children}
        elif token == tokenizer.TOKEN_TEST_FCN:
            body, assert_num = self._parse_body(file, tokenizer)
            return {'type': 'test', 'name': params[0], 'body': body, 'assert_num': assert_num}
        elif token == tokenizer.TOKEN_MAIN_FCN:
            return {'type': 'main', 'name': params[0]}
        else:
            self._raise_syntax_error(
                file, "Unexpected token at root", line)

    def _parse_if_children(self, file, tokenizer):
        children = []
        while True:
            token, params, line = tokenizer.peek_token(file)
            if token is None:
                self._raise_syntax_error(
                    file, "Missing if closing statement!", line)
            elif token != tokenizer.TOKEN_IF_END:
                children.append(self._parse_element(file, tokenizer))
            else:
                tokenizer.get_token(file)
                break
        return children

    def _parse_body(self, file, tokenizer):
        token, _, line = tokenizer.get_token(file)
        if token != tokenizer.TOKEN_BODY_START:
            self._raise_syntax_error(
                file, "Unexpected token at test function body start", line)
        assert_num = 0
        body = ""
        while True:
            token, _, line = tokenizer.get_token(file)
            if token == tokenizer.TOKEN_BODY_END:
                break
            elif token == tokenizer.TOKEN_ASSERT:
                assert_num += 1
                body += line
            elif token == tokenizer.TOKEN_TEXT:
                body += line
            else:
                self._raise_syntax_error(
                    file, "Unexpected token at test function body", line)
        return body, assert_num

    def get_main_function(self):
        for n in self._tree:
            if n['type'] == 'main':
                return n['name']

    def get_tree(self):
        return self._tree


if __name__ == "__main__":
    # Test the parser by parsing all the files in the c_src directory...
    for file in Path('c_src/').glob('*.test'):
        test = TestParser(file)
        print(test._tree)
