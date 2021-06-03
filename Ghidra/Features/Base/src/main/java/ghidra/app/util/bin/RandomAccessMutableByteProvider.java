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
package ghidra.app.util.bin;

import java.io.*;

/**
 * An implementation of ByteProvider where the underlying
 * bytes are supplied by a random access file.
 */
public class RandomAccessMutableByteProvider extends RandomAccessByteProvider implements
		MutableByteProvider {
	/**
	 * Constructs a byte provider using the specified file
	 * @param file the file to open for random access
	 * @throws FileNotFoundException if the file does not exist
	 */
	public RandomAccessMutableByteProvider(File file) throws IOException {
		super(file);
	}

	/**
	 * Constructs a byte provider using the specified file and permissions string
	 * @param file the file to open for random access
	 * @param permissions indicating permissions used for open
	 * @throws FileNotFoundException if the file does not exist
	 */
	public RandomAccessMutableByteProvider(File file, String permissions) throws IOException {
		super(file, permissions);
	}

	@Override
	public void writeByte(long index, byte value) throws IOException {
		randomAccessFile.seek(index);
		randomAccessFile.write(value);
	}

	@Override
	public void writeBytes(long index, byte[] values) throws IOException {
		randomAccessFile.seek(index);
		randomAccessFile.write(values);
	}
}
