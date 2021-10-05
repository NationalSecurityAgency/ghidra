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

import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;

/**
 * An interface for a generic random-access byte provider.
 */
public interface ByteProvider extends Closeable {

	/**
	 * A static re-usable empty {@link ByteProvider} instance. 
	 */
	public static final ByteProvider EMPTY_BYTEPROVIDER = new EmptyByteProvider();

	/**
	 * Returns the {@link FSRL} of the underlying file for this byte provider,
	 * or null if this byte provider is not associated with a file.
	 * 
	 * @return The {@link FSRL} of the underlying {@link File}, or null if no associated 
	 *   {@link File}.
	 */
	default public FSRL getFSRL() {
		File f = getFile();
		return (f != null) ? FileSystemService.getInstance().getLocalFSRL(f) : null;
	}

	/**
	 * Returns the underlying {@link File} for this {@link ByteProvider}, or null if this 
	 * {@link ByteProvider} is not associated with a {@link File}.
	 * 
	 * @return the underlying file for this byte provider
	 */
	public File getFile();

	/**
	 * Returns the name of the {@link ByteProvider}. For example, the underlying file name.
	 * 
	 * @return the name of the {@link ByteProvider} or null if there is no name
	 */
	public String getName();

	/**
	 * Returns the absolute path (similar to, but not a, URI) to the {@link ByteProvider}.
	 * For example, the complete path to the file.
	 * 
	 * @return the absolute path to the {@link ByteProvider} or null if not associated with a 
	 *   {@link File}.
	 */
	public String getAbsolutePath();

	/**
	 * Returns the length of the {@link ByteProvider}
	 * 
	 * @return the length of the {@link ByteProvider}
	 * @throws IOException if an I/O error occurs
	 */
	public long length() throws IOException;

	/**
	 * Returns true if the specified index is valid.
	 * 
	 * @param index the index in the byte provider to check
	 * @return true if the specified index is valid
	 */
	public boolean isValidIndex(long index);

	/**
	 * Releases any resources the {@link ByteProvider} may have occupied
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void close() throws IOException;

	/**
	 * Reads a byte at the specified index
	 * 
	 * @param index the index of the byte to read
	 * @return the byte read from the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public byte readByte(long index) throws IOException;

	/**
	 * Reads a byte array at the specified index
	 * 
	 * @param index the index of the byte to read
	 * @param length the number of bytes to read
	 * @return the byte array read from the specified index
	 * @throws IOException if an I/O error occurs
	 */
	public byte[] readBytes(long index, long length) throws IOException;

	/**
	 * Returns an input stream to the underlying byte provider starting at the specified index.
	 * <p>
	 * The caller is responsible for closing the returned {@link InputStream} instance.
	 * <p>
	 * If you need to override this default implementation, please document why your inputstream
	 * is needed.
	 * 
	 * @param index where in the {@link ByteProvider} to start the {@link InputStream}
	 * @return the {@link InputStream}
	 * @throws IOException  if an I/O error occurs
	 */
	default public InputStream getInputStream(long index) throws IOException {
		if (index < 0 || index > length()) {
			throw new IOException("Invalid start position: " + index);
		}
		return new ByteProviderInputStream(this, index);
	}
}
