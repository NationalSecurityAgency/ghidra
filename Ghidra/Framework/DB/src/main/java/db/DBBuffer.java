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
package db;

import java.io.IOException;
import java.io.InputStream;

/**
 * <code>DBBuffer</code> facilitates synchronized access to a ChainedBuffer.
 */
public class DBBuffer {

	final DBHandle dbh;
	final ChainedBuffer buf;

	/**
	 * Constructor for an existing ChainedBuffer.
	 * @param dbh database handle (public methods are synchronized on this object).
	 * @param buf chained buffer which is associated with the specified dbh.
	 */
	DBBuffer(DBHandle dbh, ChainedBuffer buf) {
		this.dbh = dbh;
		this.buf = buf;
	}

	/**
	 * Split this DBBuffer object into two separate DBBuffers.  This DBBuffer remains
	 * valid but its new size is equal offset.  The newly created DBBuffer is 
	 * returned.
	 * @param offset the split point.  The byte at this offset becomes the first
	 * byte within the new buffer.
	 * @return the new DBBuffer object.
	 * @throws ArrayIndexOutOfBoundsException if offset is invalid.
	 * @throws IOException thrown if an IO error occurs
	 */
	public DBBuffer split(int offset) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			return new DBBuffer(dbh, buf.split(offset));
		}
	}

	/**
	 * Set the new size for this DBBuffer object.
	 * @param size new size
	 * @param preserveData if true, existing data is preserved at the original offsets.  If false,
	 * no additional effort will be expended to preserve data.
	 * @throws IOException thrown if an IO error occurs.
	 */
	public void setSize(int size, boolean preserveData) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.setSize(size, preserveData);
		}
	}

	/**
	 * Returns the length;
	 * @return
	 */
	public int length() {
		synchronized (dbh) {
			return buf.length();
		}
	}

	/**
	 * Get the first buffer ID associated with this chained buffer.  This DBBuffer
	 * may be reinstatiated using the returned buffer ID provided subsequent changes 
	 * are not made.
	 * @return buffer ID
	 */
	public int getId() {
		synchronized (dbh) {
			return buf.getId();
		}
	}

	/**
	 * Fill the buffer over the specified range with a byte value.
	 * @param startOffset starting offset, inclusive
	 * @param endOffset ending offset, exclusive
	 * @param fillByte byte value
	 */
	public void fill(int startOffset, int endOffset, byte fillByte) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.fill(startOffset, endOffset, fillByte);
		}
	}

	/**
	 * Append the contents of the specified dbBuf onto the end of this buffer.
	 * The size of this buffer increases by the size of dbBuf.  When the operation 
	 * is complete, dbBuf object is no longer valid and must not be used.
	 * @param buffer the buffer to be appended to this buffer.
	 * @throws IOException thrown if an IO error occurs
	 */
	public void append(DBBuffer buffer) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.append(buffer.buf);
		}
	}

	/**
	 * Get the 8-bit byte value located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @return the byte value at the specified offset.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public byte getByte(int offset) throws IOException {
		synchronized (dbh) {
			return buf.getByte(offset);
		}
	}

	/**
	 * Get the byte data located at the specified offset and store into the data
	 * array  at the specified data offset.
	 * @param offset byte offset from the start of the buffer.
	 * @param data byte array to store the data.
	 * @param dataOffset offset into the data buffer
	 * @param length amount of data to read
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset, dataOffset,
	 * or length is specified.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void get(int offset, byte[] data, int dataOffset, int length) throws IOException {
		synchronized (dbh) {
			buf.get(offset, data, dataOffset, length);
		}
	}

	/**
	 * Fill buffer with data provided by InputStream.  If 
	 * stream is exhausted, the remainder of the buffer will be filled
	 * with 0's.
	 * @param in data source
	 * @throws IOException thrown if IO error occurs.
	 */
	public void fill(InputStream in) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.fill(in);
		}
	}

	/**
	 * Put a specified number of bytes from the array provided into the buffer
	 * at the specified offset.  The number of bytes stored is specified by the
	 * length specified.
	 * @param offset byte offset from start of buffer.
	 * @param bytes the byte data to be stored.
	 * @param dataOffset the starting offset into the data.
	 * @param length the number of bytes to be stored.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void put(int offset, byte[] bytes, int dataOffset, int length) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.put(offset, bytes, dataOffset, length);
		}

	}

	/**
	 * Put the bytes provided into the buffer at the specified offset. The
	 * number of bytes stored is determined by the length of the bytes
	 * array.
	 * @param offset byte offset from start of buffer.
	 * @param bytes the byte data to be stored.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided
	 * or the end of buffer was encountered while storing the data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void put(int offset, byte[] bytes) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.put(offset, bytes);
		}
	}

	/**
	 * Put the 8-bit byte value into the buffer at the specified offset. 
	 * @param offset byte offset from start of buffer.
	 * @param b the byte value to be stored.
	 * @throws ArrayIndexOutOfBoundsException if an invalid offset is provided.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void putByte(int offset, byte b) throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.putByte(offset, b);
		}
	}

	/**
	 * Get the byte data located at the specified offset.
	 * @param offset byte offset from start of buffer.
	 * @throws ArrayIndexOutOfBoundsException is thrown if an invalid offset is
	 * specified or the end of the buffer was encountered while reading the
	 * data.
	 * @throws IOException is thrown if an error occurs while accessing the
	 * underlying storage.
	 */
	public void get(int offset, byte[] data) throws IOException {
		synchronized (dbh) {
			buf.get(offset, data);
		}

	}

	/**
	 * Delete and release all underlying DataBuffers. 
	 */
	public void delete() throws IOException {
		synchronized (dbh) {
			dbh.checkTransaction();
			buf.delete();
		}
	}
}
