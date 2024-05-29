/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file compression.hh
/// \brief The Compress and Decompress classes wrapping the deflate and inflate algorithms
#ifndef __COMPRESSION__
#define __COMPRESSION__

#include "error.hh"
#ifdef LOCAL_ZLIB
#include "../zlib/zlib.h"
#else
#include <zlib.h>
#endif

namespace ghidra {

/// \brief Wrapper for the deflate algorithm
///
/// Initialize/free algorithm resources.  Provide successive arrays of bytes to compress via
/// the input() method.  Compute successive arrays of compressed bytes via the deflate() method.
class Compress {
  z_stream compStream;		///< The zlib deflate algorithm state
public:
  Compress(int4 level);		///< Initialize the deflate algorithm state
  ~Compress(void);		///< Free algorithm state resources

  /// \brief Provide the next sequence of bytes to be compressed
  ///
  /// \param buffer is a pointer to the bytes to compress
  /// \param sz is the number of bytes
  void input(uint1 *buffer,int4 sz) {
    compStream.avail_in = sz;
    compStream.next_in = buffer;
  }
  int4 deflate(uint1 *buffer,int4 sz,bool finish);	///< Deflate as much as possible into given buffer
};

/// \brief Wrapper for the inflate algorithm
///
/// Initialize/free algorithm resources. Provide successive arrays of compressed bytes via
/// the input() method. Compute successive arrays of uncompressed bytes via the inflate() method.
class Decompress {
  z_stream compStream;		///< The zlib inflate algorithm state
  bool streamFinished;		///< Set to \b true if the end of the compressed stream has been reached
public:
  Decompress(void);		///< Initialize the inflate algorithm state
  ~Decompress(void);		///< Free algorithm state resources

  /// \brief Provide the next sequence of compressed bytes
  ///
  /// \param buffer is a pointer to the compressed bytes
  /// \param sz is the number of bytes
  void input(uint1 *buffer,int4 sz) {
    compStream.next_in = buffer;
    compStream.avail_in = sz;
  }

  bool isFinished(void) const { return streamFinished; }	///< Return \b if end of compressed stream is reached
  int4 inflate(uint1 *buffer,int4 sz);	///< Inflate as much as possible into given buffer
};

/// \brief Stream buffer that performs compression
///
/// Provides an ostream filter that compresses the stream using the \e deflate algorithm.
/// The stream buffer is provided a backing stream that is the ultimate destination of the compressed bytes.
/// A front-end stream is initialized with \b this stream buffer.
/// After writing the full sequence of bytes to compressed to the front-end stream, make sure to
/// call the stream's flush() method to emit the final compressed bytes to the backing stream.
class CompressBuffer : public std::streambuf {
  static const int4 IN_BUFFER_SIZE;	///< Number of bytes in the \e input buffer
  static const int4 OUT_BUFFER_SIZE;	///< Number of bytes in the \e output buffer
  ostream &outStream;			///< The backing stream receiving compressed bytes
  uint1 *inBuffer;			///< The \e input buffer
  uint1 *outBuffer;			///< The \e output buffer
  Compress compressor;			///< Compressor state
protected:
  void flushInput(bool lastBuffer);	///< Compress the current set of bytes in the \e input buffer
  virtual int overflow(int c);		///< Pass the filled input buffer to the compressor
  virtual int sync(void);		///< Pass remaining bytes in the input buffer to the compressor
public:
  CompressBuffer(ostream &s,int4 level);	///< Constructor
  ~CompressBuffer(void);			///< Destructor
};

}

#endif
