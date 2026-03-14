<a name="roarr"></a>
# Roarr

[![GitSpo Mentions](https://gitspo.com/badges/mentions/gajus/roarr?style=flat-square)](https://gitspo.com/mentions/gajus/roarr)
[![Travis build status](http://img.shields.io/travis/gajus/roarr/master.svg?style=flat-square)](https://travis-ci.org/gajus/roarr)
[![Coveralls](https://img.shields.io/coveralls/gajus/roarr.svg?style=flat-square)](https://coveralls.io/github/gajus/roarr)
[![NPM version](http://img.shields.io/npm/v/roarr.svg?style=flat-square)](https://www.npmjs.org/package/roarr)
[![Canonical Code Style](https://img.shields.io/badge/code%20style-canonical-blue.svg?style=flat-square)](https://github.com/gajus/canonical)
[![Twitter Follow](https://img.shields.io/twitter/follow/kuizinas.svg?style=social&label=Follow)](https://twitter.com/kuizinas)

JSON logger for Node.js and browser.

* [Roarr](#roarr)
    * [Motivation](#roarr-motivation)
    * [Usage](#roarr-usage)
        * [Producing logs](#roarr-usage-producing-logs)
        * [Consuming logs](#roarr-usage-consuming-logs)
        * [Filtering logs](#roarr-usage-filtering-logs)
    * [Log message format](#roarr-log-message-format)
    * [API](#roarr-api)
        * [`adopt`](#roarr-api-adopt)
        * [`child`](#roarr-api-child)
        * [`getContext`](#roarr-api-getcontext)
        * [`trace`](#roarr-api-trace)
        * [`debug`](#roarr-api-debug)
        * [`info`](#roarr-api-info)
        * [`warn`](#roarr-api-warn)
        * [`error`](#roarr-api-error)
        * [`fatal`](#roarr-api-fatal)
    * [Middlewares](#roarr-middlewares)
    * [CLI program](#roarr-cli-program)
    * [Transports](#roarr-transports)
    * [Node.js environment variables](#roarr-node-js-environment-variables)
    * [Conventions](#roarr-conventions)
        * [Context property names](#roarr-conventions-context-property-names)
        * [Using Roarr in an application](#roarr-conventions-using-roarr-in-an-application)
    * [Recipes](#roarr-recipes)
        * [Logging errors](#roarr-recipes-logging-errors)
        * [Using with Elasticsearch](#roarr-recipes-using-with-elasticsearch)
        * [Using with Scalyr](#roarr-recipes-using-with-scalyr)
        * [Documenting use of Roarr](#roarr-recipes-documenting-use-of-roarr)


<a name="roarr-motivation"></a>
## Motivation

For a long time I have been a big fan of using [`debug`](https://github.com/visionmedia/debug). `debug` is simple to use, works in Node.js and browser, does not require configuration and it is fast. However, problems arise when you need to parse logs. Anything but one-line text messages cannot be parsed in a safe way.

To log structured data, I have been using [Winston](https://github.com/winstonjs/winston) and [Bunyan](https://github.com/trentm/node-bunyan). These packages are great for application-level logging. I have preferred Bunyan because of the [Bunyan CLI program](https://github.com/trentm/node-bunyan#cli-usage) used to pretty-print logs. However, these packages require program-level configuration – when constructing an instance of a logger, you need to define the transport and the log-level. This makes them unsuitable for use in code designed to be consumed by other applications.

Then there is [pino](https://github.com/pinojs/pino). pino is fast JSON logger, it has CLI program equivalent to Bunyan, it decouples transports, and it has sane default configuration. Unfortunately, you still need to instantiate logger instance at the application-level. This makes it more suitable for application-level logging just like Winston and Bunyan.

I needed a logger that:

* Does not block the event cycle (=fast).
* Does not require initialisation.
* Produces structured data.
* [Decouples transports](#transports).
* Has a [CLI program](#cli-program).
* Works in Node.js and browser.
* Configurable using environment variables.

In other words,

* a logger that I can use in an application code and in dependencies.
* a logger that allows to correlate logs between the main application code and the dependency code.
* a logger that works well with transports in external processes.

Roarr is this logger.

<a name="roarr-usage"></a>
## Usage

<a name="roarr-usage-producing-logs"></a>
### Producing logs

Roarr logger API for producing logs is the same in Node.js and browser.

1. Import `roarr`
2. Use any of the [API](#api) methods to log messages.

Example:

```js
import log from 'roarr';

log('foo');

```

<a name="roarr-usage-consuming-logs"></a>
### Consuming logs

Roarr logs are consumed differently in Node.js and browser.

<a name="roarr-usage-consuming-logs-node-js"></a>
#### Node.js

In Node.js, Roarr logging is disabled by default. To enable logging, you must start program with an environment variable `ROARR_LOG` set to `true`, e.g.

```bash
ROARR_LOG=true node ./index.js

```

All logs will be written to stdout.

<a name="roarr-usage-consuming-logs-browser"></a>
#### Browser

In a browser, you must implement `ROARR.write` method to read logs, e.g.

```js
import {
  ROARR,
} from 'roarr';

ROARR.write = () => {};

```

The API of the `ROARR.write` is:

```js
(message: string) => void;

```

Example implementation:

```js
import {
  ROARR,
} from 'roarr';

ROARR.write = (message) => {
  console.log(JSON.parse(message));
};

```

or if you are initializing `ROARR.write` _before_ `roarr` is loaded:

```js
// Ensure that `globalThis.ROARR` is configured.
const ROARR = globalThis.ROARR = globalThis.ROARR || {};

ROARR.write = (message) => {
  console.log(JSON.parse(message));
};

```

If your platform does not support [`globalThis`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/globalThis), use [`globalthis` polyfill](https://www.npmjs.com/package/globalthis).

<a name="roarr-usage-filtering-logs"></a>
### Filtering logs

<a name="roarr-usage-filtering-logs-node-js-1"></a>
#### Node.js

In Node.js, Roarr prints all or none logs (refer to the [`ROARR_LOG` environment variable](#environment-variables) documentation).

Use [`roarr filter` CLI program](#filter-program) to filter the logs that are written to stdout by the program, e.g.

```bash
ROARR_LOG=true node ./index.js | roarr filter '{"context.logLevel":{gt:30}}'

```

Alternatively, use a JSON processor such as [jq](https://stedolan.github.io/jq/)

<a name="roarr-usage-filtering-logs-browser-1"></a>
#### Browser

In a browser, Roarr calls `globalThis.ROARR.write` for every log message. Implement your own custom logic to filter logs, e.g.

```js
globalThis.ROARR.write = (message) => {
  const payload = JSON.parse(message);

  if (payload.context.logLevel > 30) {
    console.log(payload);
  }
};

```

<a name="roarr-log-message-format"></a>
## Log message format

|Property name|Contents|
|---|---|
|`context`|Arbitrary, user-provided structured data. See [context property names](#context-property-names).|
|`message`|User-provided message formatted using [printf](https://en.wikipedia.org/wiki/Printf_format_string).|
|`sequence`|An incremental ID.|
|`time`|Unix timestamp in milliseconds.|
|`version`|Roarr log message format version.|

Example:

```js
{
  "context": {
    "application": "task-runner",
    "hostname": "curiosity.local",
    "instanceId": "01BVBK4ZJQ182ZWF6FK4EC8FEY",
    "taskId": 1
  },
  "message": "starting task ID 1",
  "sequence": 0,
  "time": 1506776210000,
  "version": "1.0.0"
}

```

<a name="roarr-api"></a>
## API

`roarr` package exports a function with the following API:

```js
export type LoggerType =
  (
    context: MessageContextType,
    message: string,
    c?: SprintfArgumentType,
    d?: SprintfArgumentType,
    e?: SprintfArgumentType,
    f?: SprintfArgumentType,
    g?: SprintfArgumentType,
    h?: SprintfArgumentType,
    i?: SprintfArgumentType,
    k?: SprintfArgumentType
  ) => void |
  (
    message: string,
    b?: SprintfArgumentType,
    c?: SprintfArgumentType,
    d?: SprintfArgumentType,
    e?: SprintfArgumentType,
    f?: SprintfArgumentType,
    g?: SprintfArgumentType,
    h?: SprintfArgumentType,
    i?: SprintfArgumentType,
    k?: SprintfArgumentType
  ) => void;

```

To put it into words:

* First parameter can be either a string (message) or an object.
  * If first parameter is an object (context), the second parameter must be a string (message).
* Arguments after the message parameter are used to enable [printf message formatting](https://en.wikipedia.org/wiki/Printf_format_string).
  * Printf arguments must be of a primitive type (`string | number | boolean | null`).
  * There can be up to 9 printf arguments (or 8 if the first parameter is the context object).

Refer to the [Usage documentation](#usage) for common usage examples.

<a name="roarr-api-adopt"></a>
### <code>adopt</code>

```js
<T>(routine: () => Promise<T>, context: MessageContextType) => Promise<T>,

```

`adopt` function uses Node.js [`domain`](https://nodejs.org/api/domain.html) to pass-down context properties.

When using `adopt`, context properties will be added to all _all_ Roarr messages within the same asynchronous context, e.g.

```js
await log.adopt(
  async () => {
    log('foo 0');

    await log.adopt(
      () => {
        log('foo 1');
      },
      {
        baz: 'baz 1',
      },
    );
  },
  {
    bar: 'bar 0',
  },
);

// {"context":{"bar":"bar 0"},"message":"foo 0","sequence":0,"time":1531914656076,"version":"1.0.0"}
// {"context":{"bar":"bar 0","baz":"baz 1"},"message":"foo 1","sequence":1,"time":1531914656077,"version":"1.0.0"}]

```

<a name="roarr-api-adopt-requirements"></a>
#### Requirements

* `adopt` method only works in Node.js.
* You must shim Node.js using [`domain-parent`](https://github.com/gajus/domain-parent).

<a name="roarr-api-child"></a>
### <code>child</code>

```js
(context: TranslateMessageFunctionType | MessageContextType) => LoggerType,

```

The `child` function has two signatures:

1. Accepts an object.
2. Accepts a function.

<a name="roarr-api-child-object-parameter"></a>
#### Object parameter

```js
(context: MessageContextType) => LoggerType;

```

Creates a child logger appending the provided `context` object to the previous logger context.

Example:

```js
import log from 'roarr';

const childLog = log.child({
  foo: 'bar'
});

log.debug('foo 1');
childLog.debug('foo 2');

// {"context":{"logLevel":20},"message":"foo 1","sequence":0,"time":1531914529921,"version":"1.0.0"}
// {"context":{"foo":"bar","logLevel":20},"message":"foo 2","sequence":1,"time":1531914529922,"version":"1.0.0"}

```

Refer to [middlewares](#middlewares) documentation for use case examples.

<a name="roarr-api-child-function-parameter"></a>
#### Function parameter

```js
(translateMessage: TranslateMessageFunctionType) => LoggerType;

```

Creates a child logger where every message is intercepted.

Example:

```js
import log from 'roarr';

const childLog = log.child((message) => {
  return {
    ...message,
    message: message.message.replace('foo', 'bar'),
  }
});

log.debug('foo 1');
childLog.debug('foo 2');

// {"context":{"logLevel":20},"message":"foo 1","sequence":0,"time":1531914656076,"version":"1.0.0"}
// {"context":{"logLevel":20},"message":"bar 2","sequence":1,"time":1531914656077,"version":"1.0.0"}

```

<a name="roarr-api-getcontext"></a>
### <code>getContext</code>

Returns the current context.

Example:

```js
import log from 'roarr';

const childLogger = log.child({
  foo: 'bar'
});

childLogger.getContext();

// {foo: 'bar'}

```

<a name="roarr-api-trace"></a>
### <code>trace</code>
<a name="roarr-api-debug"></a>
### <code>debug</code>
<a name="roarr-api-info"></a>
### <code>info</code>
<a name="roarr-api-warn"></a>
### <code>warn</code>
<a name="roarr-api-error"></a>
### <code>error</code>
<a name="roarr-api-fatal"></a>
### <code>fatal</code>

Convenience methods for logging a message with `logLevel` context property value set to a numeric value representing the [log level](#log-levels), e.g.

```js
import log from 'roarr';

log.trace('foo');
log.debug('foo');
log.info('foo');
log.warn('foo');
log.error('foo');
log.fatal('foo');

```

Produces output:

```
{"context":{"logLevel":10},"message":"foo","sequence":0,"time":1506776210000,"version":"1.0.0"}
{"context":{"logLevel":20},"message":"foo","sequence":1,"time":1506776210000,"version":"1.0.0"}
{"context":{"logLevel":30},"message":"foo","sequence":2,"time":1506776210000,"version":"1.0.0"}
{"context":{"logLevel":40},"message":"foo","sequence":3,"time":1506776210000,"version":"1.0.0"}
{"context":{"logLevel":50},"message":"foo","sequence":4,"time":1506776210000,"version":"1.0.0"}
{"context":{"logLevel":60},"message":"foo","sequence":5,"time":1506776210000,"version":"1.0.0"}

```

<a name="roarr-middlewares"></a>
## Middlewares

Roarr logger supports middlewares implemented as [`child`](#child) message translate functions, e.g.

```js
import log from 'roarr';
import createSerializeErrorMiddleware from '@roarr/middleware-serialize-error';

const childLog = log.child(createSerializeErrorMiddleware());

const error = new Error('foo');

log.debug({error}, 'bar');
childLog.debug({error}, 'bar');

// {"context":{"logLevel":20,"error":{}},"message":"bar","sequence":0,"time":1531918373676,"version":"1.0.0"}
// {"context":{"logLevel":20,"error":{"name":"Error","message":"foo","stack":"[REDACTED]"}},"message":"bar","sequence":1,"time":1531918373678,"version":"1.0.0"}

```

Roarr middlwares enable translation of every bit of information that is used to construct a log message.

The following are the official middlewares:

* [`@roarr/middleware-serialize-error`](https://github.com/gajus/roarr-middleware-serialize-error)

Raise an issue to add your middleware of your own creation.

<a name="roarr-cli-program"></a>
## CLI program

Roarr CLI program provides ability to filter and pretty-print Roarr logs.

![CLI output demo](./.README/cli-output-demo.png)

CLI program has been moved to a separate package [`@roarr/cli`](https://github.com/gajus/roarr-cli).

```bash
npm install @roarr/cli -g

```

Explore all CLI commands and options using `roarr --help` or refer to [`@roarr/cli`](https://github.com/gajus/roarr-cli) documentation.

<a name="roarr-transports"></a>
## Transports

A transport in most logging libraries is something that runs in-process to perform some operation with the finalised log line. For example, a transport might send the log line to a standard syslog server after processing the log line and reformatting it.

Roarr does not support in-process transports.

Roarr does not support in-process transports because Node processes are single threaded processes (ignoring some technical details). Given this restriction, Roarr purposefully offloads handling of the logs to external processes so that the threading capabilities of the OS can be used (or other CPUs).

Depending on your configuration, consider one of the following log transports:

* [Beats](https://www.elastic.co/products/beats) for aggregating at a process level (written in Go).
* [logagent](https://github.com/sematext/logagent-js) for aggregating at a process level (written in JavaScript).
* [Fluentd](https://www.fluentd.org/) for aggregating logs at a container orchestration level (e.g. Kubernetes) (written in Ruby).

<a name="roarr-node-js-environment-variables"></a>
## Node.js environment variables

Use environment variables to control `roarr` behaviour.

|Name|Type|Function|Default|
|---|---|---|---|
|`ROARR_LOG`|Boolean|Enables/ disables logging.|`false`|
|`ROARR_STREAM`|`STDOUT`, `STDERR`|Name of the stream where the logs will be written.|`STDOUT`|

When using `ROARR_STREAM=STDERR`, use [`3>&1 1>&2 2>&3 3>&-`](https://stackoverflow.com/a/2381643/368691) to pipe stderr output.

<a name="roarr-conventions"></a>
## Conventions

<a name="roarr-conventions-context-property-names"></a>
### Context property names

Roarr does not have reserved context property names. However, I encourage use of the following conventions:

|Context property name|Use case|
|---|---|
|`application`|Name of the application (do not use in code intended for distribution; see `package` property instead).|
|`logLevel`|A numeric value indicating the [log level](#log-levels). See [API](#api) for the build-in loggers with a pre-set log-level.|
|`namespace`|Namespace within a package, e.g. function name. Treat the same way that you would construct namespaces when using the [`debug`](https://github.com/visionmedia/debug) package.|
|`package`|Name of the NPM package.|

The `roarr pretty-print` [CLI program](#cli-program) is using the context property names suggested in the conventions to pretty-print the logs for the developer inspection purposes.

<a name="roarr-conventions-context-property-names-log-levels"></a>
#### Log levels

The `roarr pretty-print` [CLI program](#cli-program) translates `logLevel` values to the following human-readable names:

|`logLevel`|Human-readable name|
|---|---|
|10|TRACE|
|20|DEBUG|
|30|INFO|
|40|WARN|
|50|ERROR|
|60|FATAL|

<a name="roarr-conventions-using-roarr-in-an-application"></a>
### Using Roarr in an application

To avoid code duplication, you can use a singleton pattern to export a logger instance with predefined context properties (e.g. describing the application).

I recommend to create a file `Logger.js` in the project directory. Inside this file create and export a child instance of Roarr with context parameters describing the project and the script instance, e.g.

```js
/**
 * @file Example contents of a Logger.js file.
 */

import log from 'roarr';

const Logger = log.child({
  // .foo property is going to appear only in the logs that are created using
  // the current instance of a Roarr logger.
  foo: 'bar'
});

export default Logger;

```

Roarr does not have reserved context property names. However, I encourage use of the [conventions](#conventions).

<a name="roarr-recipes"></a>
## Recipes

<a name="roarr-recipes-logging-errors"></a>
### Logging errors

This is not specific to Roarr – this suggestion applies to any kind of logging.

If you want to include an instance of [`Error`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Error) in the context, you must serialize the error.

The least-error prone way to do this is to use an existing library, e.g. [`serialize-error`](https://www.npmjs.com/package/serialize-error).

```js
import log from 'roarr';
import serializeError from 'serialize-error';

// [..]

send((error, result) => {
  if (error) {
    log.error({
      error: serializeError(error)
    }, 'message not sent due to a remote error');

    return;
  }

  // [..]
});

```

Without using serialisation, your errors will be logged without the error name and stack trace.

<a name="roarr-recipes-using-with-elasticsearch"></a>
### Using with Elasticsearch

If you are using [Elasticsearch](https://www.elastic.co/products/elasticsearch), you will want to create an [index template](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates.html).

The following serves as the ground work for the index template. It includes the main Roarr log message properties (context, message, time) and the context properties suggested in the [conventions](#conventions).

```json
{
  "mappings": {
    "log_message": {
      "_source": {
        "enabled": true
      },
      "dynamic": "strict",
      "properties": {
        "context": {
          "dynamic": true,
          "properties": {
            "application": {
              "type": "keyword"
            },
            "hostname": {
              "type": "keyword"
            },
            "instanceId": {
              "type": "keyword"
            },
            "logLevel": {
              "type": "integer"
            },
            "namespace": {
              "type": "text"
            },
            "package": {
              "type": "text"
            }
          }
        },
        "message": {
          "type": "text"
        },
        "time": {
          "format": "epoch_millis",
          "type": "date"
        }
      }
    }
  },
  "template": "logstash-*"
}

```

<a name="roarr-recipes-using-with-scalyr"></a>
### Using with Scalyr

If you are using [Scalyr](https://www.scalyr.com/), you will want to create a custom parser `RoarrLogger`:

```js
{
  patterns: {
    tsPattern: "\\w{3},\\s\\d{2}\\s\\w{3}\\s\\d{4}\\s[\\d:]+",
    tsPattern_8601: "\\d{4}-\\d{2}-\\d{2}T[\\d:.]+Z"
  }
  formats: [
    {format: "${parse=json}$"},
    {format: ".*\"time\":$timestamp=number$,.*"},
    {format: "$timestamp=tsPattern$ GMT $detail$"},
    {format: "$timestamp=tsPattern_8601$ $detail$"}
  ]
}

```

and configure the individual programs to use `RoarrLogger`. In case of Kubernetes, this means adding a `log.config.scalyr.com/attributes.parser: RoarrLogger` annotation to the associated deployment, pod or container.

<a name="roarr-recipes-documenting-use-of-roarr"></a>
### Documenting use of Roarr

If your package is using Roarr, include instructions in `README.md` describing how to enable logging, e.g.

```md
## Logging

This package is using [`roarr`](https://www.npmjs.com/package/roarr) logger to log the program's state.

Export `ROARR_LOG=true` environment variable to enable log printing to stdout.

Use [`roarr-cli`](https://github.com/gajus/roarr-cli) program to pretty-print the logs.

```
