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
import java.nio.file.AccessMode;

import org.apache.commons.collections4.map.ReferenceMap;

import ghidra.formats.gfilesystem.FSRL;
import ghidra.util.Msg;
import ghidra.util.datastruct.LRUMap;

/**
 * A {@link ByteProvider} that reads its bytes from a file.
 * 
 */
public class FileByteProvider implements ByteProvider, MutableByteProvider {

	static final int BUFFER_SIZE = 64 * 1024;
	private static final int BUFFERS_TO_PIN = 4;

	private FSRL fsrl;
	private File file;
	private RandomAccessFile raf;
	private ReferenceMap<Long, Buffer> buffers = new ReferenceMap<>();
	private LRUMap<Long, Buffer> lruBuffers = new LRUMap<>(BUFFERS_TO_PIN);	// only used to pin a small set of recently used buffers in memory.  not used for lookup
	private long currentLength;
	private AccessMode accessMode;	// probably wrong Enum class, but works for now

	/**
	 * Creates a new instance.
	 * 
	 * @param file {@link File} to open
	 * @param fsrl {@link FSRL} identity of the file
	 * @param accessMode {@link AccessMode#READ} or {@link AccessMode#WRITE}
	 * @throws IOException if error
	 */
	public FileByteProvider(File file, FSRL fsrl, AccessMode accessMode)
			throws IOException {
		this.file = file;
		this.fsrl = fsrl;
		this.accessMode = accessMode;
		this.raf = new RandomAccessFile(file, accessModeToString(accessMode));
		this.currentLength = raf.length();
	}

	/**
	 * Returns the access mode the file was opened with.
	 * 
	 * @return {@link AccessMode} used to open file
	 */
	public AccessMode getAccessMode() {
		return accessMode;
	}

	@Override
	public void close() throws IOException {
		if (raf != null) {
			raf.close();
			raf = null;
		}
		buffers.clear();
		lruBuffers.clear();
	}

	@Override
	public File getFile() {
		return file;
	}

	@Override
	public String getName() {
		return fsrl != null ? fsrl.getName() : file.getName();
	}

	@Override
	public String getAbsolutePath() {
		return fsrl != null ? fsrl.getPath() : file.getAbsolutePath();
	}

	@Override
	public FSRL getFSRL() {
		return fsrl;
	}

	@Override
	public long length() throws IOException {
		return currentLength;
	}

	@Override
	public boolean isValidIndex(long index) {
		return 0 <= index && index < currentLength;
	}

	@Override
	public byte readByte(long index) throws IOException {
		ensureBounds(index, 1);
		Buffer fileBuffer = getBufferFor(index);
		int ofs = fileBuffer.getBufferOffset(index);

		return fileBuffer.bytes[ofs];
	}

	@Override
	public byte[] readBytes(long index, long length) throws IOException {
		ensureBounds(index, length);
		if (length > Integer.MAX_VALUE) {
			throw new IllegalArgumentException();
		}
		int len = (int) length;
		byte[] result = new byte[len];
		int bytesRead = readBytes(index, result, 0, len);
		if (bytesRead != len) {
			throw new IOException("Unable to read " + len + " bytes at " + index);
		}
		return result;
	}

	/**
	 * Read bytes at the specified index into the given byte array.
	 * <p>
	 * See {@link InputStream#read(byte[], int, int)}.
	 * <p>
	 * 
	 * @param index file offset to start reading
	 * @param buffer byte array that will receive the bytes
	 * @param offset offset inside the byte array to place the bytes
	 * @param length number of bytes to read
	 * @return number of actual bytes read
	 * @throws IOException if error
	 */
	public int readBytes(long index, byte[] buffer, int offset, int length) throws IOException {
		ensureBounds(index, 0);
		length = (int) Math.min(currentLength - index, length);

		int totalBytesRead = 0;
		while (length > 0) {
			Buffer fileBuffer = getBufferFor(index);
			int ofs = fileBuffer.getBufferOffset(index);
			int bytesToReadFromThisBuffer = Math.min(fileBuffer.len - ofs, length);
			System.arraycopy(fileBuffer.bytes, ofs, buffer, totalBytesRead,
				bytesToReadFromThisBuffer);

			length -= bytesToReadFromThisBuffer;
			index += bytesToReadFromThisBuffer;
			totalBytesRead += bytesToReadFromThisBuffer;
		}
		return totalBytesRead;
	}

	@Override
	protected void finalize() {
		if (raf != null) {
			Msg.warn(this, "FAIL TO CLOSE " + file);
		}
	}

	/**
	 * Writes bytes to the specified offset in the file.
	 * 
	 * @param index the location in the file to starting writing
	 * @param buffer bytes to write
	 * @param offset offset in the buffer byte array to start 
	 * @param length number of bytes to write
	 * @throws IOException if bad {@link AccessMode} or other io error
	 */
	public synchronized void writeBytes(long index, byte[] buffer, int offset, int length)
			throws IOException {
		if (accessMode != AccessMode.WRITE) {
			throw new IOException("Not write mode");
		}

		doWriteBytes(index, buffer, offset, length);
		long writeEnd = index + length;
		currentLength = Math.max(currentLength, writeEnd);

		// after writing new bytes to the file, update
		// any buffers that we can completely fill with the contents of
		// this write buffer, and invalidate any buffers that we can't
		// completely fill (they can be re-read in a normal fashion later when needed)
		while (length > 0) {
			long bufferPos = getBufferPos(index);
			int bufferOfs = (int) (index - bufferPos);
			int bytesAvailForThisBuffer = Math.min(length, BUFFER_SIZE - bufferOfs);

			Buffer fileBuffer = buffers.get(bufferPos);
			if (fileBuffer != null) {
				if (bufferOfs == 0 && length >= BUFFER_SIZE) {
					System.arraycopy(buffer, offset, fileBuffer.bytes, 0, BUFFER_SIZE);
					fileBuffer.len = BUFFER_SIZE;
				}
				else {
					buffers.remove(bufferPos);
					lruBuffers.remove(bufferPos);
				}
			}
			index += bytesAvailForThisBuffer;
			offset += bytesAvailForThisBuffer;
			length -= bytesAvailForThisBuffer;
		}
	}

	@Override
	public void writeByte(long index, byte value) throws IOException {
		writeBytes(index, new byte[] { value }, 0, 1);
	}

	@Override
	public void writeBytes(long index, byte[] values) throws IOException {
		writeBytes(index, values, 0, values.length);
	}

	//------------------------------------------------------------------------------------
	/**
	 * Reads bytes from the file.
	 * <p>
	 * Protected by synchronized lock.  (See {@link #getBufferFor(long)}).
	 * 
	 * @param index file position of where to read
	 * @param buffer byte array that will receive bytes
	 * @return actual number of byte read
	 * @throws IOException if error
	 */
	protected int doReadBytes(long index, byte[] buffer) throws IOException {
		raf.seek(index);
		return raf.read(buffer, 0, buffer.length);
	}

	/**
	 * Writes the specified bytes to the file.
	 * <p>
	 * Protected by synchronized lock (See {@link #writeBytes(long, byte[], int, int)})
	 * 
	 * @param index file position of where to write
	 * @param buffer byte array containing bytes to write
	 * @param offset offset inside of byte array to start
	 * @param length number of bytes from buffer to write
	 * @throws IOException if error
	 */
	protected void doWriteBytes(long index, byte[] buffer, int offset, int length)
			throws IOException {
		raf.seek(index);
		raf.write(buffer, offset, length);
	}

	//------------------------------------------------------------------------------------
	private void ensureBounds(long index, long length) throws IOException {
		if (index < 0 || index > currentLength) {
			throw new IOException("Invalid index: " + index);
		}
		if (index + length > currentLength) {
			throw new IOException("Unable to read past EOF: " + index + ", " + length);
		}
	}

	private long getBufferPos(long index) {
		return (index / BUFFER_SIZE) * BUFFER_SIZE;
	}

	private synchronized Buffer getBufferFor(long pos) throws IOException {
		long bufferPos = getBufferPos(pos);
		if (bufferPos >= currentLength) {
			throw new EOFException();
		}
		Buffer buffer = buffers.get(bufferPos);
		if (buffer == null) {
			buffer = new Buffer(bufferPos, (int) Math.min(currentLength - bufferPos, BUFFER_SIZE));
			int bytesRead = doReadBytes(bufferPos, buffer.bytes);
			if (bytesRead != buffer.len) {
				buffer.len = bytesRead;
				// warn?
			}
			buffers.put(bufferPos, buffer);
		}
		lruBuffers.put(bufferPos, buffer);
		return buffer;
	}

	private static class Buffer {
		long pos;	// absolute position in file of this buffer
		int len;	// number of valid bytes in buffer
		byte[] bytes;

		Buffer(long pos, int len) {
			this.pos = pos;
			this.len = len;
			this.bytes = new byte[len];
		}

		int getBufferOffset(long filePos) throws EOFException {
			int ofs = (int) (filePos - pos);
			if (ofs >= len) {
				throw new EOFException();
			}
			return ofs;
		}
	}

	private String accessModeToString(AccessMode mode) {
		switch (mode) {
			default:
			case READ:
				return "r";
			case WRITE:
				return "rw";
		}
	}
}
