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

import java.io.IOException;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Class for determining the size of a GIF image. It loads just enough of the GIF information to 
 * follow the data block links and read the bytes until the terminator is hit.  The amount of
 * bytes read indicate the number of bytes the GIF data type is consume.
 *
 */
public class GIFResource {
	private MemBufferImageInputStream inputStream;

	public GIFResource(MemBuffer buf) throws InvalidDataTypeException {
		inputStream = new MemBufferImageInputStream(buf, ByteOrder.LITTLE_ENDIAN);
		try {
			readHeader();
			skipContents();
		}
		catch (IOException e) {
			throw new InvalidDataTypeException("Invalid GIF Data");
		}
	}

	private void readHeader() throws IOException, InvalidDataTypeException {
		byte[] bytes = new byte[6];  // MAGIC bytes
		inputStream.read(bytes);
		if (!Arrays.equals(bytes, GifDataType.MAGIC_87) &&
			!Arrays.equals(bytes, GifDataType.MAGIC_89)) {
			throw new InvalidDataTypeException("Invalid GIF Data");
		}
		inputStream.readShort();			// width
		inputStream.readShort();			// height

		int flags = inputStream.read();
		boolean globalColorTableFlag = (flags & 0x80) != 0;
		int globalColorTableSize = 2 << (flags & 7);
		inputStream.read();		// background color index
		inputStream.read();		// pixel aspect ratio

		if (globalColorTableFlag) {
			inputStream.skipBytes(3 * globalColorTableSize);
		}
	}

	private void skipContents() throws IOException, InvalidDataTypeException {
		int controlByte = inputStream.read();
		while (controlByte != 0x3b) {
			if (controlByte == 0x2c) {
				skipImage();
			}
			else if (controlByte == 0x21) {
				skipExtension();
			}
			else {
				throw new InvalidDataTypeException("Invalid GIF Data");
			}
			controlByte = inputStream.read();
		}
	}

	private void skipExtension() throws IOException {
		inputStream.read();  // skip extension type
		skipDataBlocks();
	}

	private void skipDataBlocks() throws IOException {
		int blockSize = inputStream.read();
		while (blockSize > 0) {
			inputStream.skipBytes(blockSize);
			blockSize = inputStream.read();
		}
	}

	private void skipImage() throws IOException {
		inputStream.skipBytes(8); 			// image descriptor block
		int flags = inputStream.read();  	// color table info
		boolean localColorTableFlag = (flags & 0x80) != 0;
		int localColorTableSize = 2 << (flags & 7);

		if (localColorTableFlag) {
			inputStream.skipBytes(3 * localColorTableSize);
		}

		inputStream.read();		// Code byte for LZW decoder

		skipDataBlocks();

	}

	public int getLength() {
		return inputStream.getConsumedLength();
	}

}
