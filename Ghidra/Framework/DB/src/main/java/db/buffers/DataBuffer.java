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
package db.buffers;

import java.io.*;
import java.util.Arrays;
import java.util.zip.*;

import db.Buffer;

/**
 * <code>DataBuffer</code> provides an accessible binary buffer
 * for use with a BufferMgr and BufferFile.
 */
public class DataBuffer implements Buffer, Externalizable {

	public static final long serialVersionUID = 3L;

	public static final String COMPRESSED_SERIAL_OUTPUT_PROPERTY =
		"db.buffers.DataBuffer.compressedOutput";

	private static boolean enableCompressedSerializationOutput =
		Boolean.parseBoolean(System.getProperty(COMPRESSED_SERIAL_OUTPUT_PROPERTY, "false"));

	public static void enableCompressedSerializationOutput(boolean enable) {
		System.setProperty(COMPRESSED_SERIAL_OUTPUT_PROPERTY, Boolean.toString(enable));
		enableCompressedSerializationOutput = enable;
	}

	public static boolean usingCompressedSerializationOutput() {
		return enableCompressedSerializationOutput;
	}

	private static int FORMAT_VERSION = 0xEA; // 0xEA is first version (avoided simple value like 0 or 1)

	/**
	 * NOTE: See custom serialization methods at bottom which implement compression.
	 */

	private int id;

	protected byte[] data;
	private boolean dirty = false;
	private boolean empty = false;

	/**
	 * Constructor for de-serialization
	 */
	public DataBuffer() {
	}

	/**
	 * Construct a data buffer.  A new binary buffer is created.
	 * @param bufsize buffer size
	 */
	protected DataBuffer(int bufsize) {
		this.data = new byte[bufsize];
	}

	/**
	 * Construct a data buffer.
	 * @param data binary storage array for this buffer.
	 */
	protected DataBuffer(byte[] data) {
		this.data = data;
	}

	/**
	 * Get the storage array associated with this buffer.
	 * @return byte storage array.
	 */
	protected byte[] getData() {
		return data;
	}

	/**
	 * Get the storage array associated with this buffer.
	 */
	protected void setData(byte[] data) {
		this.data = data;
	}

	/**
	 * Get the ID associated with this buffer.
	 * @return buffer ID.
	 */
	@Override
	public int getId() {
		return id;
	}

	/**
	 * Set the ID associated with this buffer.
	 * @param id buffer ID
	 */
	protected void setId(int id) {
		this.id = id;
	}

	/**
	 * Return true if this buffer contains modified data.
	 * When this buffer is released to the BufferMgr, the data is consumed and 
	 * this flag reset to false.
	 */
	public boolean isDirty() {
		return dirty;
	}

	/**
	 * Set the dirty flag.
	 * @param state flag state.  
	 */
	protected void setDirty(boolean state) {
		dirty = state;
	}

	/**
	 * Return true if this buffer is empty/unused.  Writing to empty buffer
	 * does not change the state of this flag.
	 */
	public boolean isEmpty() {
		return empty;
	}

	/**
	 * Set the empty flag.
	 * @param state flag state
	 */
	protected void setEmpty(boolean state) {
		empty = state;
	}

	@Override
	public int length() {
		return data.length;
	}

	@Override
	public void get(int offset, byte[] bytes, int dataOffset, int length)
			throws ArrayIndexOutOfBoundsException {
		System.arraycopy(data, offset, bytes, dataOffset, length);
	}

	@Override
	public void get(int offset, byte[] bytes) {
		System.arraycopy(data, offset, bytes, 0, bytes.length);
	}

	@Override
	public byte[] get(int offset, int length) throws ArrayIndexOutOfBoundsException {
		byte[] bytes = new byte[length];
		System.arraycopy(data, offset, bytes, 0, bytes.length);
		return bytes;
	}

	@Override
	public byte getByte(int offset) {
		return data[offset];
	}

	@Override
	public int getInt(int offset) {
		return ((data[offset] & 0xff) << 24) | ((data[++offset] & 0xff) << 16) |
			((data[++offset] & 0xff) << 8) | (data[++offset] & 0xff);
	}

	@Override
	public short getShort(int offset) {
		return (short) (((data[offset] & 0xff) << 8) | (data[++offset] & 0xff));
	}

	@Override
	public long getLong(int offset) {
		return (((long) data[offset] & 0xff) << 56) | (((long) data[++offset] & 0xff) << 48) |
			(((long) data[++offset] & 0xff) << 40) | (((long) data[++offset] & 0xff) << 32) |
			(((long) data[++offset] & 0xff) << 24) | (((long) data[++offset] & 0xff) << 16) |
			(((long) data[++offset] & 0xff) << 8) | ((long) data[++offset] & 0xff);
	}

	@Override
	public int put(int offset, byte[] bytes, int dataOffset, int length) {
		dirty = true;
		System.arraycopy(bytes, dataOffset, data, offset, length);
		return offset + length;
	}

	@Override
	public int put(int offset, byte[] bytes) {
		dirty = true;
		System.arraycopy(bytes, 0, data, offset, bytes.length);
		return offset + bytes.length;
	}

	@Override
	public int putByte(int offset, byte b) {
		dirty = true;
		data[offset] = b;
		return ++offset;
	}

	@Override
	public int putInt(int offset, int v) {
		dirty = true;
		data[offset] = (byte) (v >> 24);
		data[++offset] = (byte) (v >> 16);
		data[++offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	@Override
	public int putShort(int offset, short v) {
		dirty = true;
		data[offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	@Override
	public int putLong(int offset, long v) {
		dirty = true;
		data[offset] = (byte) (v >> 56);
		data[++offset] = (byte) (v >> 48);
		data[++offset] = (byte) (v >> 40);
		data[++offset] = (byte) (v >> 32);
		data[++offset] = (byte) (v >> 24);
		data[++offset] = (byte) (v >> 16);
		data[++offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	/**
	 * Sets all the values in the buffer to 0;
	 */
	public void clear() {
		Arrays.fill(data, (byte) 0);
	}

	/**
	 * Move the data within this buffer.
	 * @param src source offset within this buffer
	 * @param dest destination offset within this buffer
	 * @param length length of data to be moved
	 * @throws ArrayIndexOutOfBoundsException is thrown if parameters result in
	 * data access beyond the buffer size.
	 */
	public void move(int src, int dest, int length) {
		dirty = true;
		System.arraycopy(data, src, data, dest, length);
	}

	/**
	 * Copy data from another buffer into this buffer.
	 * @param offset offset within this buffer.
	 * @param buf source buffer
	 * @param bufOffset source buffer offset
	 * @param length amount of data to copy.
	 * @throws ArrayIndexOutOfBoundsException is thrown if parameters result in
	 * data access beyond the buffer size.
	 */
	public void copy(int offset, DataBuffer buf, int bufOffset, int length) {
		dirty = true;
		System.arraycopy(buf.data, bufOffset, data, offset, length);
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {

		boolean compress = enableCompressedSerializationOutput;

		byte[] compressedData = null;
		int compressedLen = -1;

		if (empty || data == null) {
			compress = false;
		}
		else if (compress) {
			// attempt to compress data
			compressedData = new byte[data.length];
			compressedLen = deflateData(data, compressedData);
			if (compressedLen < 0) {
				compress = false; // compression ineffective
			}
		}

		out.writeInt(FORMAT_VERSION);
		out.writeBoolean(compress);

		out.writeInt(id);
		out.writeBoolean(dirty);
		out.writeBoolean(empty);

		if (data == null) {
			out.writeInt(-1);
		}
		else {

			out.writeInt(data.length);

			if (compress) {
				out.writeInt(compressedLen); // compressed buf size
				out.write(compressedData, 0, compressedLen);
			}
			else if (data != null) {
				out.write(data);
			}
		}
	}

	/**
	 * Deflate data into compressedData array.  Both arrays must have equal lengths.
	 * @param data
	 * @param compressedData
	 * @return length of compressed data within the compressedData array, or -1 if 
	 * unable to compress.
	 */
	private static int deflateData(byte[] data, byte[] compressedData) {

		Deflater deflate = new Deflater(Deflater.BEST_COMPRESSION, true);
		deflate.setStrategy(Deflater.HUFFMAN_ONLY);
		deflate.setInput(data, 0, data.length);
		deflate.finish();

		int compressedDataOffset = 0;

		while (!deflate.finished() && compressedDataOffset < compressedData.length) {
			compressedDataOffset += deflate.deflate(compressedData, compressedDataOffset,
				compressedData.length - compressedDataOffset, Deflater.SYNC_FLUSH);
		}

		if (!deflate.finished()) {
			return -1;
		}

		return compressedDataOffset;
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {

		int formatVersion = in.readInt();
		if (formatVersion != FORMAT_VERSION) {
			throw new IOException("Unsupported DataBuffer serialization");
		}

		boolean compressed = in.readBoolean();

		id = in.readInt();
		dirty = in.readBoolean();
		empty = in.readBoolean();
		int len = in.readInt();

		data = null;

		if (len >= 0) {
			data = new byte[len];
			if (compressed) {
				int compressedLen = in.readInt();
				byte[] compressedData = new byte[compressedLen];
				in.readFully(compressedData);
				inflateData(compressedData, data);
			}
			else {
				in.readFully(data);
			}
		}
	}

	/**
	 * Perform an unsigned data comparison 
	 * @param otherData other data to be compared
	 * @param offset offset within this buffer
	 * @param len length of data within this buffer
	 * @return unsigned comparison result
	 * @throws ArrayIndexOutOfBoundsException if specified region is not 
	 * contained within this buffer.
	 */
	public int unsignedCompareTo(byte[] otherData, int offset, int len) {

		int otherLen = otherData.length;
		int otherOffset = 0;
		int n = Math.min(len, otherLen);
		while (n-- != 0) {
			int b = data[offset++] & 0xff;
			int otherByte = otherData[otherOffset++] & 0xff;
			if (b != otherByte) {
				return b - otherByte;
			}
		}
		return len - otherLen;
	}

	/**
	 * Inflate compressedData into a properly sized data array.  
	 * @param compressedData array containing compressed data
	 * @param data target data array size to receive fully inflated data.
	 * @throws IOException
	 */
	private static void inflateData(byte[] compressedData, byte[] data) throws IOException {

		Inflater inflater = new Inflater(true);
		inflater.setInput(compressedData, 0, compressedData.length);

		try {
			int off = 0;
			while (!inflater.finished() && off < data.length) {
				off += inflater.inflate(data, off, data.length - off);
				if (inflater.needsDictionary()) { // unexpected
					throw new IOException("DataBuffer dictionary error");
				}
			}
			if (!inflater.finished()) {
				throw new IOException("DataBuffer inflate size error");
			}
		}
		catch (DataFormatException e) {
			throw new IOException("DataBuffer inflation failed", e);
		}
	}

}
