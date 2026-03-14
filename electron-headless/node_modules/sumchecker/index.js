/*
Copyright 2016, 2017, 2019 Mark Lee and contributors

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

const debug = require('debug')('sumchecker')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const { promisify } = require('util')

const readFile = promisify(fs.readFile)

const CHECKSUM_LINE = /^([\da-fA-F]+) ([ *])(.+)$/

class ErrorWithFilename extends Error {
  constructor (filename) {
    super()
    this.filename = filename
  }
}

class ChecksumMismatchError extends ErrorWithFilename {
  constructor (filename) {
    super(filename)
    this.message = `Generated checksum for "${filename}" did not match expected checksum.`
  }
}

class ChecksumParseError extends Error {
  constructor (lineNumber, line) {
    super()
    this.lineNumber = lineNumber
    this.line = line
    this.message = `Could not parse checksum file at line ${lineNumber}: ${line}`
  }
}

class NoChecksumFoundError extends ErrorWithFilename {
  constructor (filename) {
    super(filename)
    this.message = `No checksum found in checksum file for "${filename}".`
  }
}

class ChecksumValidator {
  constructor (algorithm, checksumFilename, options) {
    this.algorithm = algorithm
    this.checksumFilename = checksumFilename
    this.checksums = null

    if (options && options.defaultTextEncoding) {
      this.defaultTextEncoding = options.defaultTextEncoding
    } else {
      this.defaultTextEncoding = 'utf8'
    }
  }

  encoding (binary) {
    return binary ? 'binary' : this.defaultTextEncoding
  }

  parseChecksumFile (data) {
    debug('Parsing checksum file')
    this.checksums = {}
    let lineNumber = 0
    for (const line of data.trim().split(/[\r\n]+/)) {
      lineNumber += 1
      const result = CHECKSUM_LINE.exec(line)
      if (result === null) {
        debug(`Could not parse line number ${lineNumber}`)
        throw new ChecksumParseError(lineNumber, line)
      } else {
        result.shift()
        const [checksum, binaryMarker, filename] = result
        const isBinary = binaryMarker === '*'

        this.checksums[filename] = [checksum, isBinary]
      }
    }
    debug('Parsed checksums:', this.checksums)
  }

  async readFile (filename, binary) {
    debug(`Reading "${filename} (binary mode: ${binary})"`)
    return readFile(filename, this.encoding(binary))
  }

  async validate (baseDir, filesToCheck) {
    if (typeof filesToCheck === 'string') {
      filesToCheck = [filesToCheck]
    }

    const data = await this.readFile(this.checksumFilename, false)
    this.parseChecksumFile(data)
    return this.validateFiles(baseDir, filesToCheck)
  }

  async validateFile (baseDir, filename) {
    return new Promise((resolve, reject) => {
      debug(`validateFile: ${filename}`)

      const metadata = this.checksums[filename]
      if (!metadata) {
        return reject(new NoChecksumFoundError(filename))
      }

      const [checksum, binary] = metadata
      const fullPath = path.resolve(baseDir, filename)
      debug(`Reading file with "${this.encoding(binary)}" encoding`)
      const stream = fs.createReadStream(fullPath, { encoding: this.encoding(binary) })
      const hasher = crypto.createHash(this.algorithm, { defaultEncoding: 'binary' })
      hasher.on('readable', () => {
        const data = hasher.read()
        if (data) {
          const calculated = data.toString('hex')

          debug(`Expected checksum: ${checksum}; Actual: ${calculated}`)
          if (calculated === checksum) {
            resolve()
          } else {
            reject(new ChecksumMismatchError(filename))
          }
        }
      })
      stream.pipe(hasher)
    })
  }

  async validateFiles (baseDir, filesToCheck) {
    return Promise.all(filesToCheck.map(filename => this.validateFile(baseDir, filename)))
  }
}

const sumchecker = async function sumchecker (algorithm, checksumFilename, baseDir, filesToCheck) {
  return new ChecksumValidator(algorithm, checksumFilename).validate(baseDir, filesToCheck)
}

sumchecker.ChecksumMismatchError = ChecksumMismatchError
sumchecker.ChecksumParseError = ChecksumParseError
sumchecker.ChecksumValidator = ChecksumValidator
sumchecker.NoChecksumFoundError = NoChecksumFoundError

module.exports = sumchecker
