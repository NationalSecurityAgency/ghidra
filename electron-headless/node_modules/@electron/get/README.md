# @electron/get

> Download Electron release artifacts

[![CircleCI](https://circleci.com/gh/electron/get.svg?style=shield)](https://circleci.com/gh/electron/get)
[![NPM package](https://img.shields.io/npm/v/@electron/get)](https://npm.im/@electron/get)

## Usage

### Simple: Downloading an Electron Binary ZIP

```typescript
import { download } from '@electron/get';

// NB: Use this syntax within an async function, Node does not have support for
//     top-level await as of Node 12.
const zipFilePath = await download('4.0.4');
```

### Advanced: Downloading a macOS Electron Symbol File


```typescript
import { downloadArtifact } from '@electron/get';

// NB: Use this syntax within an async function, Node does not have support for
//     top-level await as of Node 12.
const zipFilePath = await downloadArtifact({
  version: '4.0.4',
  platform: 'darwin',
  artifactName: 'electron',
  artifactSuffix: 'symbols',
  arch: 'x64',
});
```

### Specifying a mirror

To specify another location to download Electron assets from, the following options are
available:

* `mirrorOptions` Object
  * `mirror` String (optional) - The base URL of the mirror to download from.
  * `nightlyMirror` String (optional) - The Electron nightly-specific mirror URL.
  * `customDir` String (optional) - The name of the directory to download from, often scoped by version number.
  * `customFilename` String (optional) - The name of the asset to download.
  * `resolveAssetURL` Function (optional) - A function allowing customization of the url used to download the asset.

Anatomy of a download URL, in terms of `mirrorOptions`:

```
https://github.com/electron/electron/releases/download/v4.0.4/electron-v4.0.4-linux-x64.zip
|                                                     |       |                           |
-------------------------------------------------------       -----------------------------
                        |                                                   |
              mirror / nightlyMirror                  |    |         customFilename
                                                       ------
                                                         ||
                                                      customDir
```

Example:

```typescript
import { download } from '@electron/get';

const zipFilePath = await download('4.0.4', {
  mirrorOptions: {
    mirror: 'https://mirror.example.com/electron/',
    customDir: 'custom',
    customFilename: 'unofficial-electron-linux.zip'
  }
});
// Will download from https://mirror.example.com/electron/custom/unofficial-electron-linux.zip

const nightlyZipFilePath = await download('8.0.0-nightly.20190901', {
  mirrorOptions: {
    nightlyMirror: 'https://nightly.example.com/',
    customDir: 'nightlies',
    customFilename: 'nightly-linux.zip'
  }
});
// Will download from https://nightly.example.com/nightlies/nightly-linux.zip
```

`customDir` can have the placeholder `{{ version }}`, which will be replaced by the version
specified (without the leading `v`). For example:

```javascript
const zipFilePath = await download('4.0.4', {
  mirrorOptions: {
    mirror: 'https://mirror.example.com/electron/',
    customDir: 'version-{{ version }}',
    platform: 'linux',
    arch: 'x64'
  }
});
// Will download from https://mirror.example.com/electron/version-4.0.4/electron-v4.0.4-linux-x64.zip
```

#### Using environment variables for mirror options
Mirror options can also be specified via the following environment variables:
* `ELECTRON_CUSTOM_DIR` - Specifies the custom directory to download from.
* `ELECTRON_CUSTOM_FILENAME` - Specifies the custom file name to download.
* `ELECTRON_MIRROR` - Specifies the URL of the server to download from if the version is not a nightly version.
* `ELECTRON_NIGHTLY_MIRROR` - Specifies the URL of the server to download from if the version is a nightly version.

### Overriding the version downloaded

The version downloaded can be overriden by setting the `ELECTRON_CUSTOM_VERSION` environment variable.
Setting this environment variable will override the version passed in to `download` or `downloadArtifact`.

## How It Works

This module downloads Electron to a known place on your system and caches it
so that future requests for that asset can be returned instantly.  The cache
locations are:

* Linux: `$XDG_CACHE_HOME` or `~/.cache/electron/`
* MacOS: `~/Library/Caches/electron/`
* Windows: `%LOCALAPPDATA%/electron/Cache` or `~/AppData/Local/electron/Cache/`

By default, the module uses [`got`](https://github.com/sindresorhus/got) as the
downloader. As a result, you can use the same [options](https://github.com/sindresorhus/got#options)
via `downloadOptions`.

### Progress Bar

By default, a progress bar is shown when downloading an artifact for more than 30 seconds. To
disable, set the `ELECTRON_GET_NO_PROGRESS` environment variable to any non-empty value, or set
`quiet` to `true` in `downloadOptions`. If you need to monitor progress yourself via the API, set
`getProgressCallback` in `downloadOptions`, which has the same function signature as `got`'s
[`downloadProgress` event callback](https://github.com/sindresorhus/got#ondownloadprogress-progress).

### Proxies

Downstream packages should utilize the `initializeProxy` function to add HTTP(S) proxy support. If
the environment variable `ELECTRON_GET_USE_PROXY` is set, it is called automatically.
