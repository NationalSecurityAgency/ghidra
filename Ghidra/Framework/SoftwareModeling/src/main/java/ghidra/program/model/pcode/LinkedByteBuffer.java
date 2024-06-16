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
package ghidra.program.model.pcode;

import java.io.IOException;
import java.io.InputStream;

/**
 * A byte buffer that is stored as a linked list of pages.  Each page holds BUFFER_SIZE bytes.
 * A Position object acts as an iterator over the whole buffer.  The buffer can be populated
 * from a stream, either all at once or "as needed" when a Position object iterates past
 * the current cached set of bytes.
 */
public class LinkedByteBuffer {

	/**
	 * An iterator into the byte buffer
	 */
	public static class Position {
		public LinkedByteBuffer buffer;		// The buffer object
		public ArrayIter seqIter;			// Linked-list node of the current page
		public byte[] array;				// The byte data of the current page
		public int current;					// Position within page of current byte

		/**
		 * Set this to be a copy of another Position
		 * @param pos is the Position being copied
		 */
		public void copy(Position pos) {
			seqIter = pos.seqIter;
			array = pos.array;
			current = pos.current;
		}

		/**
		 * Return the byte at the current Position. Do not advance the Position.
		 * @return the byte at this Position
		 */
		public final byte getByte() {
			return array[current];
		}

		/**
		 * Lookahead exactly one byte, without advancing this Position
		 * @return the byte after the one at this Position
		 * @throws DecoderException if the end of stream is reached
		 */
		public final byte getBytePlus1() throws DecoderException {
			int plus1 = current + 1;
			if (plus1 == array.length) {
				ArrayIter iter = seqIter.next;
				if (iter == null) {
					iter = buffer.readNextPage(seqIter);
				}
				return iter.array[0];
			}
			return array[plus1];
		}

		/**
		 * Advance this Position by exactly one byte and return the next byte.
		 * @return the next byte
		 * @throws DecoderException if the end of stream is reached
		 */
		public final byte getNextByte() throws DecoderException {
			byte res = array[current];
			current += 1;
			if (current != array.length) {
				return res;
			}
			if (seqIter.next == null) {
				seqIter = buffer.readNextPage(seqIter);
			}
			else {
				seqIter = seqIter.next;
			}
			array = seqIter.array;
			current = 0;
			return res;
		}

		/**
		 * Advance this Position by the specified number of bytes
		 * @param skip is the specified number of bytes to advance
		 * @throws DecoderException if the end of stream is reached
		 */
		public final void advancePosition(int skip) throws DecoderException {
			while (array.length - current <= skip) {
				skip -= (array.length - current);
				if (seqIter.next == null) {
					seqIter = buffer.readNextPage(seqIter);
				}
				else {
					seqIter = seqIter.next;
				}
				array = seqIter.array;
				current = 0;
			}
			current += skip;
		}
	}

	/**
	 * A linked-list page node
	 */
	public static class ArrayIter {
		public ArrayIter next;		// The next-node in the list
		public byte[] array;		// Byte data contained in this page
	}

	public final static int BUFFER_SIZE = 1024;

	private ArrayIter initialBuffer;	// The initial page in the linked list
	private int byteCount;				// Total number of bytes cached
	private int maxCount;				// Maximum bytes that can be cached
	private ArrayIter currentBuffer;	// Last page in the linked list
	private int currentPos;				// Last byte successfully cached in last page
	private int padValue;				// Padding data
	private InputStream asNeededStream = null;	// If non-null, a stream that is read as needed
	private String description;		// Describes source of bytes for use in error messages

	public LinkedByteBuffer(int max, int pad, String desc) {
		initialBuffer = new ArrayIter();
		currentBuffer = initialBuffer;
		byteCount = 0;
		currentPos = 0;
		padValue = pad;
		maxCount = max;
		initialBuffer.array = new byte[BUFFER_SIZE];
		initialBuffer.next = null;
		description = desc;
	}

	/**
	 * Close the "as needed" stream, if configure.
	 * @throws IOException for problems closing the stream
	 */
	public void close() throws IOException {
		if (asNeededStream != null) {
			asNeededStream.close();
		}
	}

	/**
	 * Set up this buffer so that it reads in pages as needed.  The initial page is read
	 * immediately.  Additional pages are read via readNextPage() through the Position methods.
	 * @param stream is the stream to read from
	 * @param start will hold the initial buffer
	 * @throws IOException for problems reading data from the stream
	 */
	public void ingestStreamAsNeeded(InputStream stream, Position start) throws IOException {
		asNeededStream = stream;
		currentPos = readPage(stream, initialBuffer);
		if (currentPos < BUFFER_SIZE) {
			pad();
		}
		getStartPosition(start);
		initialBuffer = null;		// Let garbage collection pick up pages that are already parsed
	}

	/**
	 * Ingest stream up to the first 0 byte or until maxCount bytes is reached.
	 * Store the bytes on the heap in BUFFER_SIZE chunks.
	 * @param stream is the input
	 * @throws IOException for errors reading from the stream
	 */
	public void ingestStreamToNextTerminator(InputStream stream) throws IOException {
		int tok = stream.read();
		if (tok <= 0) {
			return;
		}
		for (;;) {
			if (byteCount > maxCount) {
				throw new IOException("Response buffer size exceded for: " + description);
			}
			do {
				if (currentPos == BUFFER_SIZE) {
					break;
				}
				currentBuffer.array[currentPos++] = (byte) tok;
				tok = stream.read();
			}
			while (tok > 0);
			byteCount += currentPos;
			if (tok <= 0) {
				return;		// Reached terminator or end of stream, ingest is finished
			}
			// Set up next buffer
			currentBuffer.next = new ArrayIter();
			currentBuffer = currentBuffer.next;
			currentBuffer.array = new byte[BUFFER_SIZE];
			currentPos = 0;
		}
	}

	/**
	 * Read a page of data into the given buffer.  The buffer must already be allocated and
	 * will be entirely filled, unless end-of-stream is reached.  The number of bytes
	 * actually read into the buffer is returned.
	 * @param stream is the stream
	 * @param buffer is the allocated buffer
	 * @return the number of bytes read
	 * @throws IOException for problems reading from the stream
	 */
	private int readPage(InputStream stream, ArrayIter buffer) throws IOException {
		int len = maxCount - byteCount;
		if (len > BUFFER_SIZE) {
			len = BUFFER_SIZE;
		}
		int pos = 0;
		do {
			int readLen = stream.read(currentBuffer.array, pos, len - pos);
			if (readLen < 0) {
				break;
			}
			pos += readLen;
		}
		while (pos < len);
		byteCount += pos;
		return pos;
	}

	/**
	 * Read the stream until the end of stream is encountered or until maxCount bytes is reached.
	 * Store the bytes on the heap in BUFFER_SIZE chunks.
	 * @param stream is the input
	 * @throws IOException for errors reading from the stream
	 */
	public void ingestStream(InputStream stream) throws IOException {
		while (byteCount < maxCount) {
			int pos = readPage(stream, currentBuffer);
			if (pos < BUFFER_SIZE) {
				currentPos += pos;
				break;
			}
			// Set up next buffer
			currentBuffer.next = new ArrayIter();
			currentBuffer = currentBuffer.next;
			currentBuffer.array = new byte[BUFFER_SIZE];
			currentPos = 0;
		}
	}

	/**
	 * Ingest bytes directly from a byte array.
	 * If these bytes would cause the total number of bytes ingested to exceed
	 * the maximum (maxCount) bytes set for this buffer, an exception is thrown.
	 * This can be called multiple times to read in different chunks.
	 * @param byteArray is the array of bytes
	 * @param off is the index of the first byte to ingest
	 * @param sz is the number of bytes to ingest
	 * @throws IOException if the max number of bytes to ingest is exceeded
	 */
	public void ingestBytes(byte[] byteArray, int off, int sz) throws IOException {
		for (int i = 0; i < sz; ++i) {
			byte tok = byteArray[off + i];
			if (currentPos == BUFFER_SIZE) {
				// Set up next buffer
				currentBuffer.next = new ArrayIter();
				currentBuffer = currentBuffer.next;
				currentBuffer.array = new byte[BUFFER_SIZE];
				currentPos = 0;
			}
			currentBuffer.array[currentPos++] = tok;
			byteCount += 1;
			if (byteCount > maxCount) {
				throw new IOException("Response buffer size exceded for: " + description);
			}
		}
	}

	/**
	 * Add the padValue to the end of the buffer
	 */
	public void pad() {
		if (currentPos == BUFFER_SIZE) {
			byteCount += currentPos;
			currentBuffer.next = new ArrayIter();
			currentBuffer = currentBuffer.next;
			currentBuffer.array = new byte[1];
			currentPos = 0;
		}

		currentBuffer.array[currentPos++] = (byte) padValue;
	}

	public void getStartPosition(Position position) {
		position.array = initialBuffer.array;
		position.current = 0;
		position.seqIter = initialBuffer;
	}

	/**
	 * Read the next page of data.  The new ArrayIter is added to the linked list, its
	 * byte buffer is allocated, and data is read into the buffer.
	 * If the end of stream is reached, padding is added.
	 * @param buffer is the ArrayIter currently at the end of the linked list
	 * @return the newly allocated ArrayIter
	 * @throws DecoderException if there are errors reading from the stream
	 */
	private ArrayIter readNextPage(ArrayIter buffer) throws DecoderException {
		if (asNeededStream == null) {
			throw new DecoderException("Unexpected end of stream");
		}
		currentBuffer = new ArrayIter();
		buffer.next = currentBuffer;
		currentBuffer.array = new byte[BUFFER_SIZE];
		try {
			currentPos = readPage(asNeededStream, currentBuffer);
		}
		catch (IOException e) {
			throw new DecoderException(e.getMessage());
		}
		if (currentPos < BUFFER_SIZE) {
			pad();
		}
		return buffer.next;
	}
}
