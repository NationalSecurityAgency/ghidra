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
import ghidra.util.Msg;

/**
 * An implementation of ByteProvider where the underlying
 * bytes are supplied by a random access file.
 * <p>
 * Note: this implementation is not thread-safe, and using an instance of this
 * class from multiple threads will result in reading incorrect data and/or
 * {@link ArrayIndexOutOfBoundsException}s.
 * <p>
 * See {@link SynchronizedByteProvider} as a solution.
 * <p>
 * @deprecated See {@link FileByteProvider} as replacement ByteProvider.
 */
@Deprecated(since = "10.1", forRemoval = true)
public class RandomAccessByteProvider implements ByteProvider {
	protected File file;
	protected GhidraRandomAccessFile randomAccessFile;
	private FSRL fsrl;
	private long fileLength;

	/**
	 * Constructs a {@link ByteProvider} using the specified {@link File}.
	 * 
	 * @param file the {@link File} to open for random access
	 * @throws IOException if the {@link File} does not exist or other error
	 */
	public RandomAccessByteProvider(File file) throws IOException {
		this(file, "r");
	}

	/**
	 * Constructs a {@link ByteProvider} using the specified {@link File} and {@link FSRL}
	 *
	 * @param file the {@link File} to open for random access
	 * @param fsrl the {@link FSRL} to use for the {@link File}'s path
	 * @throws IOException if the {@link File} does not exist or other error
	 */
	public RandomAccessByteProvider(File file, FSRL fsrl) throws IOException {
		this(file, fsrl, "r");
	}

	/**
	 * Constructs a {@link ByteProvider} using the specified {@link File} and permissions
	 * 
	 * @param file the {@link File} to open for random access
	 * @param permissions indicating permissions used for open
	 * @throws IOException if the {@link File} does not exist or other error
	 */
	public RandomAccessByteProvider(File file, String permissions) throws IOException {
		this(file, null, permissions);
	}

	private RandomAccessByteProvider(File file, FSRL fsrl, String permissions) throws IOException {
		this.file = file;
		this.fsrl = fsrl;
		this.randomAccessFile = new GhidraRandomAccessFile(file, permissions);
		this.fileLength = randomAccessFile.length();
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	/**
	 * Sets the {@link FSRL} of this {@link ByteProvider}
	 *
	 * @param fsrl the {@link FSRL} to assign to this byte provider
	 */
	public void setFSRL(FSRL fsrl) {
		this.fsrl = fsrl;
	}

	@Override
	public File getFile() {
		return file;
	}

	@Override
	public String getName() {
		return fsrl == null ? file.getName() : fsrl.getName();
	}

	@Override
	public String getAbsolutePath() {
		return fsrl == null ? file.getAbsolutePath() : fsrl.getPath();
	}

	@Override
	public InputStream getInputStream(long index) throws IOException {
		FileInputStream is = new FileInputStream(file);
		is.skip(index);
		return is;
	}

	@Override
	public void close() throws IOException {
		randomAccessFile.close();
	}

	@Override
	public long length() {
		return fileLength;
	}

	@Override
	public boolean isValidIndex(long index) {
		return 0 <= index && index < fileLength;
	}

	@Override
	public byte readByte(long index) throws IOException {
		randomAccessFile.seek(index);
		return randomAccessFile.readByte();
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		byte[] b = new byte[(int) length];
		if (index > fileLength) {
			throw new EOFException(
				"Invalid file offset " + index + " while reading " + file.getName());
		}
		if (index + length > fileLength) {
			Msg.trace(this, "Read at EOF, can't return partial buffer, throwing IOException: " +
				file.getName());
			throw new EOFException("EOF: unable to read " + length + " bytes at " + index);
		}
		randomAccessFile.seek(index);
		int nRead = randomAccessFile.read(b);
		if (nRead != length) {
			throw new IOException("Unable to read " + length + " bytes");
		}
		return b;
	}
	
	@Override
	public String toString() {
		return "RandomAccessByteProvider [\n  file=" + file + ",\n  fsrl=" + fsrl +
			",\n  fileLength=" + fileLength + "\n]";
	}	
}
