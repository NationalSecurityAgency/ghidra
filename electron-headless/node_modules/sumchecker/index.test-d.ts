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

import * as sumchecker from '.';
import { ChecksumParseError, ChecksumValidator } from '.';

await sumchecker('sha256', 'test/fixture/example.sha256sum', 'test/fixture', 'example');
await sumchecker('sha256', 'test/fixture/example.sha256sum', 'test/fixture', ['example']);
try {
  await sumchecker('sha256', 'test/fixture/invalid.sha256sum', 'test/fixture', ['example']);
} catch (error) {
  if (!(error instanceof ChecksumParseError)) {
    throw new Error('Does not throw ChecksumParseError correctly');
  }
}

const validator = new ChecksumValidator('sha256', 'test/fixture/example.sha256sum')
await validator.validate('test/fixture', 'example')
