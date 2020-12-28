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
package ghidra.program.database.mem;

import java.io.IOException;
import java.util.ConcurrentModificationException;

import org.apache.commons.lang3.StringUtils;

import db.*;

/**
 * FileBytes provides access to the all the byte values (both original and modified) from an
 * imported file. 
 */
public class FileBytes {

	final FileBytesAdapter adapter;

	private final long id;
	private final String filename;
	private final long fileOffset;
	private final long size;

	private DBBuffer[] originalBuffers;
	private DBBuffer[] layeredBuffers;
	private boolean invalid = false;

	public FileBytes(FileBytesAdapter adapter, DBRecord record) throws IOException {
		this.adapter = adapter;
		this.id = record.getKey();
		this.filename = record.getString(FileBytesAdapter.FILENAME_COL);
		this.fileOffset = record.getLongValue(FileBytesAdapter.OFFSET_COL);
		this.size = record.getLongValue(FileBytesAdapter.SIZE_COL);
		refresh(record);
	}

	synchronized boolean refresh(DBRecord record) throws IOException {

		String f = record.getString(FileBytesAdapter.FILENAME_COL);
		long offset = record.getLongValue(FileBytesAdapter.OFFSET_COL);
		long sz = record.getLongValue(FileBytesAdapter.SIZE_COL);
		if (offset != fileOffset || sz != size || !StringUtils.equals(f, filename)) {
			return false;
		}

		BinaryField field = (BinaryField) record.getFieldValue(FileBytesAdapter.BUF_IDS_COL);

		int[] bufferIds = new BinaryCodedField(field).getIntArray();
		originalBuffers = new DBBuffer[bufferIds.length];
		for (int i = 0; i < bufferIds.length; i++) {
			originalBuffers[i] = adapter.getBuffer(bufferIds[i]);
		}

		field = (BinaryField) record.getFieldValue(FileBytesAdapter.LAYERED_BUF_IDS_COL);
		bufferIds = new BinaryCodedField(field).getIntArray();
		layeredBuffers = new DBBuffer[bufferIds.length];
		for (int i = 0; i < bufferIds.length; i++) {
			layeredBuffers[i] = adapter.getBuffer(bufferIds[i], originalBuffers[i]);
		}
		return true;
	}

	long getId() {
		return id;
	}

	/**
	 * Returns the name of the file that supplied the bytes.
	 * @return the name of the file that supplied the bytes.
	 */
	public String getFilename() {
		return filename;
	}

	/**
	 * Returns the offset in the original file from where these bytes originated. Normally this will
	 * be 0, but in the case where the program is actually a piece in some other file (e.g. tar,zip),
	 * this will be the offset into the file corresponding to the first byte in this FileBytes object.
	 * 
	 * @return  the offset in the original file from where these bytes originated.
	 */
	public long getFileOffset() {
		return fileOffset;
	}

	/**
	 * Returns the number of bytes from the original source file that are stored in the database.
	 * @return  the number of bytes from the original source file that are stored in the database.
	 */
	public long getSize() {
		return size;
	}

	/**
	 * Returns the (possibly modified) byte at the given offset for this file bytes object.
	 * @param offset the offset into the file bytes for the byte to retrieve.
	 * @return the (possibly modified) byte at the given offset for this file bytes object.
	 * @throws IOException if there is a problem reading the database.
	 * @throws IndexOutOfBoundsException if the given offset is invalid.
	 */
	public synchronized byte getModifiedByte(long offset) throws IOException {
		return getByte(layeredBuffers, offset);
	}

	/**
	 * Returns the original byte value at the given offset for this file bytes object.
	 * @param offset the offset into the file bytes for the byte to retrieve.
	 * @return the original byte at the given offset for this file bytes object.
	 * @throws IOException if there is a problem reading the database.
	 * @throws IndexOutOfBoundsException if the given offset is invalid.
	 */
	public synchronized byte getOriginalByte(long offset) throws IOException {
		return getByte(originalBuffers, offset);
	}

	/**
	 * Tries to get b.length (possibly modified) bytes from this FileBytes entry at the given offset into the file
	 *  bytes.  May return fewer bytes if the requested length is beyond the end of the file bytes.
	 *  
	 * @param offset the offset into the files bytes to start.
	 * @param b the byte array to populate.
	 * @return the number of bytes actually populated.
	 * @throws IOException if there is an error reading from the database
	 */
	public synchronized int getModifiedBytes(long offset, byte[] b) throws IOException {
		return getBytes(layeredBuffers, offset, b, 0, b.length);
	}

	/**
	 * Tries to get b.length original bytes from this FileBytes entry at the given offset into the file
	 *  bytes.  May return fewer bytes if the requested length is beyond the end of the file bytes.
	 *  
	 * @param offset the offset into the files bytes to start.
	 * @param b the byte array to populate.
	 * @return the number of bytes actually populated.
	 * @throws IOException if there is an error reading from the database
	 */
	public synchronized int getOriginalBytes(long offset, byte[] b) throws IOException {
		return getBytes(originalBuffers, offset, b, 0, b.length);
	}

	/**
	 * Tries to get length (possibly modified) bytes from the files starting at the given offset and put them 
	 * into the given byte array at the specified offset into the byte array.  May return
	 * fewer bytes if the requested length is beyond the end of the file bytes.
	 * 
	 * @param offset the offset into the files bytes to start.
	 * @param b the byte array to populate.
	 * @param off the offset into the byte array.
	 * @param length the number of bytes to get.
	 * @return the number of bytes actually populated.
	 * @throws IOException if there is an error reading from the database
	 * @throws IndexOutOfBoundsException if the destination offset and length would exceed the
	 * size of the buffer b.
	 */
	public synchronized int getModifiedBytes(long offset, byte[] b, int off, int length)
			throws IOException {
		return getBytes(layeredBuffers, offset, b, off, length);
	}

	/**
	 * Tries to get length (original) bytes from the files starting at the given offset and put them 
	 * into the given byte array at the specified offset into the byte array.  May return
	 * fewer bytes if the requested length is beyond the end of the file bytes.
	 * 
	 * @param offset the offset into the files bytes to start.
	 * @param b the byte array to populate.
	 * @param off the offset into the byte array.
	 * @param length the number of bytes to get.
	 * @return the number of bytes actually populated.
	 * @throws IOException if there is an error reading from the database
	 * @throws IndexOutOfBoundsException if the destination offset and length would exceed the
	 * size of the buffer b.
	 */
	public synchronized int getOriginalBytes(long offset, byte[] b, int off, int length)
			throws IOException {
		return getBytes(originalBuffers, offset, b, off, length);
	}

	void checkValid() {
		if (invalid) {
			throw new ConcurrentModificationException();
		}
	}

	synchronized void invalidate() {
		invalid = true;
	}

	/**
	 * Changes the byte at the given offset to the given value. Note, the 
	 * original byte can still be accessed via {@link #getOriginalByte(long)}
	 * If the byte is changed more than once, only the original value is preserved.
	 * 
	 * @param offset the offset into the file bytes.
	 * @param b the new byte value;
	 * @throws IOException if the write to the database fails.
	 */
	synchronized void putByte(long offset, byte b) throws IOException {

		checkValid();

		if (offset < 0 || offset >= size) {
			throw new IndexOutOfBoundsException();
		}

		// The max buffer size will be the size of the first buffer. (If more than
		// one buffer exists, then the first buffer will be the true max size.  If only one buffer,
		// then its actual size can be used as the max size and it won't matter.)
		int maxBufferSize = layeredBuffers[0].length();

		int dbBufferIndex = (int) (offset / maxBufferSize);
		int localOffset = (int) (offset % maxBufferSize);
		layeredBuffers[dbBufferIndex].putByte(localOffset, b);
	}

	/**
	 * Changes the bytes at the given offset to the given values. Note, the 
	 * original bytes can still be accessed via {@link #getOriginalBytes(long, byte[])}
	 * If the bytes are changed more than once, only the original values are preserved.
	 * 
	 * @param offset the offset into the file bytes.
	 * @param b a byte array with the new values to write.
	 * @return the number of bytes written
	 * @throws IOException if the write to the database fails.
	 */
	synchronized int putBytes(long offset, byte[] b) throws IOException {
		return putBytes(offset, b, 0, b.length);
	}

	/**
	 * Changes the bytes at the given offset to the given values. Note, the 
	 * original bytes can still be accessed via {@link #getOriginalBytes(long, byte[], int, int)}
	 * If the bytes are changed more than once, only the original values are preserved.
	 * 
	 * @param offset the offset into the file bytes.
	 * @param b a byte array with the new values to write.
	 * @param off the offset into the byte array to get the bytes to write.
	 * @param length the number of bytes to write.
	 * @return the number of bytes written
	 * @throws IOException if the write to the database fails.
	 */
	synchronized int putBytes(long offset, byte[] b, int off, int length) throws IOException {

		checkValid();

		if (b == null) {
			throw new NullPointerException();
		}
		else if (off < 0 || length < 0 || length > b.length - off) {
			throw new IndexOutOfBoundsException();
		}
		else if (length == 0) {
			return 0;
		}

		// adjust size if asking length is more than we have
		length = (int) Math.min(length, size - offset);
		if (length == 0) {
			return 0;
		}

		// The max buffer size will be the size of the first buffer. (If more than
		// one buffer exists, then the first buffer will be the true max size.  If only one buffer,
		// then its actual size can be used as the max size and it won't matter.)
		int maxBufferSize = layeredBuffers[0].length();
		long fileBytesOffset = offset;
		int byteArrayOffset = off;
		int n = length;

		while (n > 0) {
			int dbBufferIndex = (int) (fileBytesOffset / maxBufferSize);
			int localOffset = (int) (fileBytesOffset % maxBufferSize);
			int writeLen = Math.min(maxBufferSize - localOffset, n);
			layeredBuffers[dbBufferIndex].put(localOffset, b, byteArrayOffset, writeLen);
			n -= writeLen;
			fileBytesOffset += writeLen;
			byteArrayOffset += writeLen;
		}
		return length;
	}

	private byte getByte(DBBuffer[] buffers, long offset) throws IOException {

		checkValid();

		if (offset < 0 || offset >= size) {
			throw new IndexOutOfBoundsException();
		}

		// The max buffer size will be the size of the first buffer. (If more than
		// one buffer exists, then the first buffer will be the true max size.  If only one buffer,
		// then its actual size can be used as the max size and it won't matter.)
		int maxBufferSize = buffers[0].length();

		int dbBufferIndex = (int) (offset / maxBufferSize);
		int localOffset = (int) (offset % maxBufferSize);
		return buffers[dbBufferIndex].getByte(localOffset);
	}

	private int getBytes(DBBuffer[] buffers, long offset, byte[] b, int off, int length)
			throws IOException {

		checkValid();

		if (off < 0 || length < 0 || length > b.length - off) {
			throw new IndexOutOfBoundsException();
		}
		else if (length == 0) {
			return 0;
		}

		// adjust size if asking length is more than we have
		length = (int) Math.min(length, size - offset);
		if (length == 0) {
			return 0;
		}

		// The max buffer size will be the size of the first buffer. (If more than
		// one buffer exists, then the first buffer will be the true max size.  If only one buffer,
		// then its actual size can be used as the max size and it won't matter.)
		int maxBufferSize = buffers[0].length();
		long fileBytesOffset = offset;
		int byteArrayOffset = off;
		int n = length;

		while (n > 0) {
			int dbBufferIndex = (int) (fileBytesOffset / maxBufferSize);
			int localOffset = (int) (fileBytesOffset % maxBufferSize);
			int readLen = Math.min(maxBufferSize - localOffset, n);
			buffers[dbBufferIndex].get(localOffset, b, byteArrayOffset, readLen);
			n -= readLen;
			fileBytesOffset += readLen;
			byteArrayOffset += readLen;
		}
		return length;
	}

	@Override
	public String toString() {
		return getFilename();
	}

	@Override
	public int hashCode() {
		return (int) (id ^ (id >>> 32));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		FileBytes other = (FileBytes) obj;
		if (adapter != other.adapter) {
			return false;
		}
		if (id != other.id) {
			return false;
		}
		if (invalid != other.invalid) {
			return false;
		}
		return true;
	}

}
