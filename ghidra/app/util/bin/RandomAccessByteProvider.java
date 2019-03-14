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

import java.io.*;

/**
 * An implementation of ByteProvider where the underlying
 * bytes are supplied by a random access file.
 * <p>
 * Note: this implementation is not thread-safe, and using an instance of this
 * class from multiple threads will result in reading incorrect data and/or
 * {@link ArrayIndexOutOfBoundsException}s.
 * <p>
 * See {@link SynchronizedByteProvider} as a solution.
 */
public class RandomAccessByteProvider implements ByteProvider {
	protected File file;
	protected GhidraRandomAccessFile randomAccessFile;
	private FSRL fsrl;

	/**
	 * Constructs a byte provider using the specified file
	 * @param file the file to open for random access
	 * @throws FileNotFoundException if the file does not exist
	 */
	public RandomAccessByteProvider(File file) throws IOException {
		this.file = file;
		this.randomAccessFile = new GhidraRandomAccessFile(file, "r");
	}

	/**
	 * Constructs a byte provider using the specified file and FSRL.
	 *
	 * @param file the file to open for random access
	 * @param fsrl the FSRL to use for the file's path
	 * @throws FileNotFoundException if the file does not exist
	 */
	public RandomAccessByteProvider(File file, FSRL fsrl) throws IOException {
		this.file = file;
		this.fsrl = fsrl;
		this.randomAccessFile = new GhidraRandomAccessFile(file, "r");
	}

	/**
	 * Constructs a byte provider using the specified file and permissions string
	 * @param file the file to open for random access
	 * @param string indicating permissions used for open
	 * @throws FileNotFoundException if the file does not exist
	 */
	public RandomAccessByteProvider(File file, String permissions) throws IOException {
		this.file = file;
		this.randomAccessFile = new GhidraRandomAccessFile(file, permissions);
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	/**
	 * Sets the {@link FSRL} of this byte provider.
	 *
	 * @param fsrl the FSRL to assign to this byte provider
	 */
	public void setFSRL(FSRL fsrl) {
		this.fsrl = fsrl;
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#getFile()
	 */
	@Override
	public File getFile() {
		return file;
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#getName()
	 */
	@Override
	public String getName() {
		return fsrl == null ? file.getName() : fsrl.getName();
	}

	@Override
	public String getAbsolutePath() {
		return fsrl == null ? file.getAbsolutePath() : fsrl.getPath();
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#getInputStream(long)
	 */
	@Override
	public InputStream getInputStream(long index) throws IOException {
		FileInputStream is = new FileInputStream(file);
		is.skip(index);
		return is;
	}

	/**
	 * Closes the underlying random-access file.
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	public void close() throws IOException {
		randomAccessFile.close();
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#length()
	 */
	@Override
	public long length() throws IOException {
		return randomAccessFile.length();
	}

	@Override
	public boolean isValidIndex(long index) {
		try {
			return index >= 0 && index < randomAccessFile.length();
		}
		catch (IOException e) {
		}
		return false;
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#readByte(long)
	 */
	@Override
	public byte readByte(long index) throws IOException {
		randomAccessFile.seek(index);
		return randomAccessFile.readByte();
	}

	/**
	 * @see ghidra.app.util.bin.ByteProvider#readBytes(long, long)
	 */
	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		randomAccessFile.seek(index);
		byte[] b = new byte[(int) length];
		int nRead = randomAccessFile.read(b);
		if (nRead != length) {
			throw new IOException("Unable to read " + length + " bytes");
		}
		return b;
	}
}
