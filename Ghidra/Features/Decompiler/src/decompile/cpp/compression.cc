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
#include "compression.hh"

namespace ghidra {

/// The compression \b level ranges from 1-9 from faster/least compression to slower/most compression.
/// Use a \b level of 0 for no compression and -1 for the \e default compression level.
/// \param level is the compression level
Compress::Compress(int4 level)

{
  compStream.zalloc = Z_NULL;
  compStream.zfree = Z_NULL;
  compStream.opaque = Z_NULL;
  int4 ret = deflateInit(&compStream, level);
  if (ret != Z_OK)
    throw LowlevelError("Could not initialize deflate stream state");
}

Compress::~Compress(void)

{
  deflateEnd(&compStream);
}

/// Return the number of bytes of output space still available.  Output may be limited by the amount
/// of space in the output buffer or the amount of data available in the current input buffer.
/// \param buffer is where compressed bytes are stored
/// \param sz is the size, in bytes, of the buffer
/// \param finish is set to \b true if this is the final buffer to add to the stream
/// \return the number of output bytes still available
int4 Compress::deflate(uint1 *buffer,int4 sz,bool finish)

{
  int flush = finish ? Z_FINISH : Z_NO_FLUSH;
  compStream.avail_out = sz;
  compStream.next_out = buffer;

  int ret = ::deflate(&compStream, flush);
  if (ret == Z_STREAM_ERROR)
    throw LowlevelError("Error compressing stream");
  return compStream.avail_out;
}

Decompress::Decompress(void)

{
  streamFinished = false;
  compStream.zalloc = Z_NULL;
  compStream.zfree = Z_NULL;
  compStream.opaque = Z_NULL;
  compStream.avail_in = 0;
  compStream.next_in = Z_NULL;
  int ret = inflateInit(&compStream);
  if (ret != Z_OK)
    throw LowlevelError("Could not initialize inflate stream state");
}

/// Return the number of bytes of output space still available.  Output may be limited by the amount
/// of space in the output buffer or the amount of data available in the current input buffer.
/// \param buffer is where uncompressed bytes are stored
/// \param sz is the size, in bytes, of the buffer
/// \return the number of output bytes still available
int4 Decompress::inflate(uint1 *buffer,int4 sz)

{
  compStream.avail_out = sz;
  compStream.next_out = buffer;

  int ret = ::inflate(&compStream, Z_NO_FLUSH);
  switch (ret) {
  case Z_NEED_DICT:
  case Z_DATA_ERROR:
  case Z_MEM_ERROR:
  case Z_STREAM_ERROR:
    throw LowlevelError("Error decompressing stream");
  case Z_STREAM_END:
    streamFinished = true;
    break;
  default:
    break;
  }

  return compStream.avail_out;
}

Decompress::~Decompress(void)

{
  inflateEnd(&compStream);
}

const int4 CompressBuffer::IN_BUFFER_SIZE = 4096;
const int4 CompressBuffer::OUT_BUFFER_SIZE = 4096;

/// \param s is the backing output stream
/// \param level is the level of compression
CompressBuffer::CompressBuffer(ostream &s,int4 level)
  : outStream(s), compressor(level)
{
  inBuffer = new uint1[IN_BUFFER_SIZE];
  outBuffer = new uint1[OUT_BUFFER_SIZE];
  setp((char *)inBuffer,(char *)inBuffer + IN_BUFFER_SIZE-1);
}

CompressBuffer::~CompressBuffer(void)

{
  delete [] inBuffer;
  delete [] outBuffer;
}

/// The compressor is called repeatedly and its output is written to the backing stream
/// until the compressor can no longer fill the \e output buffer.
/// \param lastBuffer is \b true if this is the final set of bytes to add to the compressed stream
void CompressBuffer::flushInput(bool lastBuffer)

{
  int len = pptr() - pbase();
  compressor.input((uint1 *)pbase(),len);
  int4 outAvail;
  do {
    outAvail = OUT_BUFFER_SIZE;
    outAvail = compressor.deflate(outBuffer,outAvail,lastBuffer);
    outStream.write((char *)outBuffer,OUT_BUFFER_SIZE-outAvail);
  } while(outAvail == 0);
  pbump(-len);
}

/// \param c is the final character filling the buffer
/// \return the written character
int CompressBuffer::overflow(int c)

{
  if (c != EOF) {
    *pptr() = c;
    pbump(1);
  }
  flushInput(false);
  return c;
}

/// \return 0 for success
int CompressBuffer::sync(void)

{
  flushInput(true);
  return 0;
}

}
