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
package ghidra.file.formats.cramfs;

import java.io.*;

import ghidra.app.util.bin.ByteProvider;

public class LazyCramFsInputStream extends InputStream {
	private CramFsBlockReader cramFsBlockReader;
	private InputStream currentDecompressedBlockInputStream = new ByteArrayInputStream(new byte[0]);
	private int currentCompressedBlockIndex;

	/**
	 * Constructor for lazy cramfs input stream.
	 * @param provider byte provider for the input stream.
	 * @param cramfsInode the parent node for the input stream.
	 * @param isLittleEndian returns true if the input stream is little endian.
	 * @throws IOException if there is an error when creating the input stream. 
	 */
	public LazyCramFsInputStream(ByteProvider provider, CramFsInode cramfsInode,
			boolean isLittleEndian) throws IOException {
		cramFsBlockReader = new CramFsBlockReader(provider, cramfsInode, isLittleEndian);
	}

	@Override
	public int read() throws IOException {

		int byteRead = currentDecompressedBlockInputStream.read();

		if (byteRead == -1) {
			if (currentCompressedBlockIndex < cramFsBlockReader.getNumBlockPointers()) {
				currentDecompressedBlockInputStream =
					cramFsBlockReader.readDataBlockDecompressed(currentCompressedBlockIndex);
				byteRead = currentDecompressedBlockInputStream.read();
				currentCompressedBlockIndex++;
			}
		}
		return byteRead;
	}
}
