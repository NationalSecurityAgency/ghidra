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

import java.io.*;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * StreamProcessor implementation to decompress the data as it is being read.
 *
 * CaRT zlib decompress. Reimplementation from Ghidra's default to not
 * reinitialize the inflater between calls.
 */
public class CartV1StreamDecompressor extends CartV1StreamProcessor {
	private Inflater inflater;

	/**
	 * Construct a stream decompressor.
	 *
	 * @param delegate InputStream to read and apply decompression
	 * @throws CartInvalidCartException If the CaRT data is invalid and/or missing ZLIB header
	 */
	public CartV1StreamDecompressor(InputStream delegate) throws CartInvalidCartException {
		this(new PushbackInputStream(delegate, 2));
	}

	/**
	 * Construct a stream decompressor.
	 *
	 * @param delegate PushbackInputStream to read and apply decompression
	 * @throws CartInvalidCartException If the CaRT data is invalid and/or missing ZLIB header
	 */
	public CartV1StreamDecompressor(PushbackInputStream delegate) throws CartInvalidCartException {
		super(delegate);

		inflater = new Inflater(false);

		boolean validHeaderBytes = false;
		byte[] headerBytes = new byte[2];
		try {
			delegate.read(headerBytes, 0, 2);

			// Check that the header bytes are valid values
			for (byte[] zlibBytes : CartV1Constants.ZLIB_HEADER_BYTES) {
				// On the first match, set true and stop
				if (Arrays.equals(headerBytes, zlibBytes)) {
					validHeaderBytes = true;
					break;
				}
			}

			delegate.unread(headerBytes);

			if (!validHeaderBytes) {
				throw new IOException();
			}
		}
		catch (IOException e) {
			throw new CartInvalidCartException("CaRT compression format error");
		}
	}

	/**
	 * Read the next chunk in the stream and decompress
	 *
	 * @return True if more data is now available, False otherwise.
	 * @throws IOException If there is a read failure of the data
	 */
	@Override
	protected boolean readNextChunk() throws IOException {
		byte[] compressedBytes = new byte[DEFAULT_BUFFER_SIZE];
		byte[] decompressedBytes = null;

		// Reset the current chunk and offset
		currentChunk = null;
		chunkPos = 0;

		if (inflater == null || inflater.finished()) {
			return false;
		}

		if (inflater.needsInput()) {
			int bytesRead = delegate.read(compressedBytes);

			if (bytesRead <= 0) {
				return false;
			}

			inflater.setInput(compressedBytes, 0, bytesRead);
		}

		try {
			decompressedBytes = new byte[DEFAULT_BUFFER_SIZE];
			int bytesDecompressed = inflater.inflate(decompressedBytes);

			if (bytesDecompressed <= 0) {
				return false;
			}

			currentChunk = Arrays.copyOf(decompressedBytes, bytesDecompressed);
		}
		catch (DataFormatException e) {
			throw new IOException("CaRT decompression failed: " + e.getMessage());
		}

		return currentChunk != null && currentChunk.length > 0;

	}
}
