# boolean

boolean converts lots of things to boolean.

## Status

| Category         | Status                                                                                                                                     |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Version          | [![npm](https://img.shields.io/npm/v/boolean)](https://www.npmjs.com/package/boolean)                                                      |
| Dependencies     | ![David](https://img.shields.io/david/thenativeweb/boolean)                                                                                |
| Dev dependencies | ![David](https://img.shields.io/david/dev/thenativeweb/boolean)                                                                            |
| Build            | ![GitHub Actions](https://github.com/thenativeweb/boolean/workflows/Release/badge.svg?branch=main) |
| License          | ![GitHub](https://img.shields.io/github/license/thenativeweb/boolean)                                                                      |

## Installation

```shell
$ npm install boolean
```

## Quick start

First you need to add a reference to boolean in your application:

```javascript
const { boolean, isBooleanable } = require('boolean');
```

If you use TypeScript, use the following code instead:

```typescript
import { boolean, isBooleanable } from 'boolean';
```

To verify a value for its boolean value, call the `boolean` function and provide the value in question as parameter:

```javascript
console.log(boolean('true')); // => true
```

The `boolean` function considers the following values to be equivalent to `true`:

-   `true` (boolean)
-   `'true'` (string)
-   `'TRUE'` (string)
-   `'t'` (string)
-   `'T'` (string)
-   `'yes'` (string)
-   `'YES'` (string)
-   `'y'` (string)
-   `'Y'` (string)
-   `'on'` (string)
-   `'ON'` (string)
-   `'1'` (string)
-   `1` (number)

In addition to the primitive types mentioned above, boolean also supports their object wrappers `Boolean`, `String`, and `Number`.

_Please note that if you provide a `string` or a `String` object, it will be trimmed._

All other values, including `undefined` and `null` are considered to be `false`.

### Figuring out whether a value can be considered to be boolean

From time to time, you may not want to directly convert a value to its boolean equivalent, but explicitly check whether it looks like a boolean. E.g., although `boolean('F')` returns `false`, the string `F` at least looks like a boolean, in contrast to something such as `123` (for which `boolean(123)` would also return `false`).

To figure out whether a value can be considered to be a boolean, use the `isBooleanable` function:

```javascript
console.log(isBooleanable('true')); // => true
```

The `isBooleanable` function considers all of the above mentioned values to be reasonable boolean values, and additionally, also the following ones:

-   `false` (boolean)
-   `'false'` (string)
-   `'FALSE'` (string)
-   `'f'` (string)
-   `'F'` (string)
-   `'no'` (string)
-   `'NO'` (string)
-   `'n'` (string)
-   `'N'` (string)
-   `'off'` (string)
-   `'OFF'` (string)
-   `'0'` (string)
-   `0` (number)

## Running quality assurance

To run quality assurance for this module use [roboter](https://www.npmjs.com/package/roboter):

```shell
$ npx roboter
```
