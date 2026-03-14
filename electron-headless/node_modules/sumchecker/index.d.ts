/*
Copyright 2019 Mark Lee and contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

declare function sumchecker(algorithm: string, checksumFilename: string, baseDir: string, filesToCheck: string[] | string): Promise<void>;

declare namespace sumchecker {
  type ChecksumOptions = {
    defaultTextEncoding?: string;
  };

  class ErrorWithFilename extends Error {
    constructor(filename: string);
  }

  class ChecksumMismatchError extends ErrorWithFilename {
    constructor(filename: string);
  }

  class ChecksumParseError extends Error {
    constructor(lineNumber: number, line: string);
  }

  class NoChecksumFoundError extends ErrorWithFilename {
    constructor(filename: string);
  }

  class ChecksumValidator {
    constructor(algorithm: string, checksumFilename: string, options?: ChecksumOptions);
    encoding(binary: boolean): string;
    parseChecksumFile(data: string): void;
    readFile(filename: string, binary: boolean): Promise<string>;
    validate(baseDir: string, filesToCheck: string[] | string): Promise<void>;
    validateFile(baseDir: string, filename: string): Promise<void>;
    validateFiles(baseDir: string, filesToCheck: string[]): Promise<void>;
  }
}

export = sumchecker
