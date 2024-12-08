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
package ghidra.file.formats.cart;

import java.io.IOException;
import java.io.InputStream;

/**
 * Generic buffered InputStream processor base class. Subclasses should
 * implement per-chunk processing.
 */
public abstract class CartV1StreamProcessor extends InputStream {
	/**
	 * Default buffer size to be used for input or output internal buffering
	 */
	@SuppressWarnings("unused")
	protected static final int DEFAULT_BUFFER_SIZE = 1024 * 64;

	/**
	 * Delegate for InputStrem from which to read
	 */
	protected InputStream delegate;

	/**
	 * Internal current chunk that has been read and processed and is awaiting
	 * upstream access.
	 */
	protected byte[] currentChunk;

	/**
	 * Current position in the current chunk buffer.
	 */
	protected int chunkPos;

	/**
	 * Construct a stream processor with the provided delegate.
	 *
	 * @param delegate InputStream to read and apply processing
	 */
	public CartV1StreamProcessor(InputStream delegate) {
		this.delegate = delegate;
	}

	/**
	 * Implements an InputStream compatible read()
	 *
	 * @return The value of the next byte in the stream
	 * @throws IOException If there is a read failure of the data
	 */
	@Override
	public int read() throws IOException {
		if (!ensureChunkAvailable()) {
			return -1;
		}
		byte b = currentChunk[chunkPos];
		chunkPos++;

		return Byte.toUnsignedInt(b);
	}

	/**
	 * Implements an InputStream compatible read(buffer, offset, length)
	 *
	 * @param b The buffer in which to read the bytes
	 * @param off Offset within the output offer to copy
	 * @param len Length of bytes to read into the output buffer
	 * @return The number of bytes copied to the output buffer
	 * @throws IOException If there is a read failure of the data
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (!ensureChunkAvailable()) {
			return -1;
		}

		int bytesAvail = currentChunk.length - chunkPos;
		int bytesToCopy = Math.min(len, bytesAvail);
		System.arraycopy(currentChunk, chunkPos, b, off, bytesToCopy);
		chunkPos += bytesToCopy;
		return bytesToCopy;
	}

	/**
	 * Close the InputStream delegate.
	 */
	@Override
	public void close() throws IOException {
		delegate.close();
	}

	/**
	 * Function implemented by subclasses to do the stream processing of next
	 * chunk in stream.
	 *
	 * @return True if more data is now available, False otherwise.
	 * @throws IOException If there is a read failure of the data
	 */
	protected abstract boolean readNextChunk() throws IOException;

	private boolean ensureChunkAvailable() throws IOException {
		return currentChunk == null || chunkPos >= currentChunk.length ? readNextChunk() : true;
	}
}
