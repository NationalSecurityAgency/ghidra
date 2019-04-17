/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.lang;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * A class for dynamically collecting a stream of bytes and then later dumping those bytes to a stream
 * It allows the bytes to be edited in the middle of collection
 *
 */
public class PackedBytes {
	private byte[] out;
	private int bytecnt;

	public PackedBytes(int startlen) {
		out = new byte[startlen];
		bytecnt = 0;
	}

	public int size() {
		return bytecnt;
	}

	/**
	 * Inspect the middle of the byte stream accumulated so far
	 * @param streampos is the index of the byte to inspect
	 * @return a byte value from the stream
	 */
	public int getByte(int streampos) {
		return out[streampos];
	}

	/**
	 * Overwrite bytes that have already been written into the stream 
	 * @param streampos is the index of the byte to overwrite
	 * @param val is the value to overwrite with
	 */
	public void insertByte(int streampos, int val) {
		out[streampos] = (byte) val;
	}

	/**
	 * Dump a single byte to the packed byte stream
	 * @param val is the byte to be written
	 */
	public void write(int val) {
		int newcount = bytecnt + 1;
		if (newcount > out.length)
			out = Arrays.copyOf(out, Math.max(out.length << 1, newcount));
		out[bytecnt] = (byte) val;
		bytecnt = newcount;
	}

	public int find(int start, int val) {
		while (start < bytecnt) {
			if (out[start] == val)
				return start;
			start += 1;
		}
		return -1;
	}

	/**
	 * Write the accumulated packed byte stream onto the output stream
	 * @param s is the output stream receiving the bytes
	 * @throws IOException
	 */
	public void writeTo(OutputStream s) throws IOException {
		s.write(out, 0, bytecnt);
	}

}
