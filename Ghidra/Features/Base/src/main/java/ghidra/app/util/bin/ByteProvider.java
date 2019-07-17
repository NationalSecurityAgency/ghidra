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

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;

import java.io.*;

/**
 * An interface for a generic random-access byte provider.
 */
public interface ByteProvider extends Closeable {

	/**
	 * Returns the {@link FSRL} of the underlying file for this byte provider,
	 * or null if this byte provider is not associated with a file.
	 * <p>
	 * @return {@link FSRL} of the underlying file, or null if no associated file.
	 */
	default public FSRL getFSRL() {
		File f = getFile();
		return (f != null) ? FileSystemService.getInstance().getLocalFSRL(f) : null;
	}

	/**
	 * Returns the underlying file for this byte
	 * provider. Or null if this byte provider is
	 * not associated with a file.
	 * @return the underlying file for this byte provider
	 */
	public File getFile();

	/**
	 * Returns the name of the byte provider.
	 * For example, the underlying file name.
	 * @return the name of the byte provider or null
	 */
	public String getName();

	/**
	 * Returns the absolute path (similar to, but not a, URI) to the byte provider.
	 * For example, the complete path to the file.
	 * @return the absolute path to the byte provider or null
	 */
	public String getAbsolutePath();

	/**
	 * Returns the length of the underlying provider.
	 * @return the length of the underlying provider
	 * @throws IOException if an I/O error occurs
	 */
	public long length() throws IOException;

	/**
	 * Returns true if the specified index is valid.
	 * @param index the index in the byte provider
	 * @return returns true if the specified index is valid
	 * @exception IOException if an I/O error occurs
	 */
	public boolean isValidIndex(long index);

	/**
	 * Releases any resources the provider may have occupied.
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void close() throws IOException;

	/**
	 * Reads a byte at the specified index.
	 * @param index the index to read the byte
	 * @return the byte read from the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public byte readByte(long index) throws IOException;

	/**
	 * Reads a byte array at the specified index.
	 * @param index the index to read the byte array
	 * @param length the number of elements to read
	 * @return the byte array read from the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public byte[] readBytes(long index, long length) throws IOException;

	/**
	 * Returns an input stream to the underlying byte provider starting at
	 * the specified index
	 * <p>
	 * The caller is responsible for closing the returned {@link InputStream} instance.
	 * <p>
	 * @param index the index to initialize the input stream
	 * @return the input stream
	 * @throws IOException  if an I/O error occurs
	 */
	public InputStream getInputStream(long index) throws IOException;
}
