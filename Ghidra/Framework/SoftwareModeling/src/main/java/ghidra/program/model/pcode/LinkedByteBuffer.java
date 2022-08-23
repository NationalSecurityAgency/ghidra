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

public class LinkedByteBuffer {

	public static class Position {
		public ArrayIter seqIter;
		public byte[] array;
		public int current;

		public void copy(Position pos) {
			seqIter = pos.seqIter;
			array = pos.array;
			current = pos.current;
		}

		public final byte getByte() {
			return array[current];
		}

		public final byte getBytePlus1() throws DecoderException {
			int plus1 = current + 1;
			if (plus1 == array.length) {
				ArrayIter iter = seqIter.next;
				if (iter == null) {
					throw new DecoderException("Unexpected end of stream");
				}
				return iter.array[0];
			}
			return array[plus1];
		}

		public final byte getNextByte() throws DecoderException {
			byte res = array[current];
			current += 1;
			if (current != array.length) {
				return res;
			}
			seqIter = seqIter.next;
			if (seqIter == null) {
				throw new DecoderException("Unexpected end of stream");
			}
			array = seqIter.array;
			current = 0;
			return res;
		}

		public final void advancePosition(int skip) throws DecoderException {
			while (array.length - current <= skip) {
				skip -= (array.length - current);
				seqIter = seqIter.next;
				if (seqIter == null) {
					throw new DecoderException("Unexpected end of stream");
				}
				array = seqIter.array;
				current = 0;
			}
			current += skip;
		}
	}

	public static class ArrayIter {
		public ArrayIter next;
		public byte[] array;
	}

	public final static int BUFFER_SIZE = 1024;

	private ArrayIter initialBuffer;
	private int byteCount;
	private int maxCount;
	private ArrayIter currentBuffer;
	private int currentPos;
	private String source;

	public LinkedByteBuffer(int max, String src) {
		initialBuffer = new ArrayIter();
		currentBuffer = initialBuffer;
		byteCount = 0;
		currentPos = 0;
		maxCount = max;
		initialBuffer.array = new byte[BUFFER_SIZE];
		initialBuffer.next = null;
		source = src;
	}

	public void ingestStream(InputStream stream) throws IOException {
		int tok = stream.read();
		if (tok <= 0) {
			return;
		}
		for (;;) {
			if (byteCount > maxCount) {
				throw new IOException("Response buffer size exceded for: " + source);
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
	 * Add a particular byte to the buffer
	 * @param val is the byte value to add
	 */
	public void pad(int val) {
		if (currentPos == BUFFER_SIZE) {
			byteCount += currentPos;
			currentBuffer.next = new ArrayIter();
			currentBuffer = currentBuffer.next;
			currentBuffer.array = new byte[1];
			currentPos = 0;
		}

		currentBuffer.array[currentPos++] = (byte) val;
	}

	public void getStartPosition(Position position) {
		position.array = initialBuffer.array;
		position.current = 0;
		position.seqIter = initialBuffer;
	}
}
