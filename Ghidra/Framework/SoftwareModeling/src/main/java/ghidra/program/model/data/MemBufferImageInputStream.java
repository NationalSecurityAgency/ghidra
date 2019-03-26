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
package ghidra.program.model.data;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

import java.io.IOException;
import java.nio.ByteOrder;

import javax.imageio.stream.ImageInputStreamImpl;

/**
 * ImageInputStream for reading images that wraps a MemBuffer to get the bytes.  Adds a method
 * to find out how many bytes were read by the imageReader to read the image.
 *
 */
public class MemBufferImageInputStream extends ImageInputStreamImpl {
	private MemBuffer buf;

	public MemBufferImageInputStream(MemBuffer buf, ByteOrder byteOrder) {
		this.buf = buf;
		setByteOrder(byteOrder);
	}

	public int getConsumedLength() {
		return (int) streamPos;
	}

	@Override
	public int read() throws IOException {
		try {
			return buf.getByte((int) (streamPos++)) & 0xff;
		}
		catch (MemoryAccessException e) {
			streamPos--;
			return -1;
		}
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		for (int i = 0; i < len; i++) {
			int value = read();
			if (value < 0) {
				return i;
			}
			b[off + i] = (byte) value;
		}
		return len;
	}

}
