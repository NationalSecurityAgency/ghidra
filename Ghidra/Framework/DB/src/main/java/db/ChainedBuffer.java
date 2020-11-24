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
import java.util.Arrays;

import db.buffers.BufferMgr;
import db.buffers.DataBuffer;
import ghidra.util.exception.AssertException;

/**
 * <code>DBBuffer</code> provides storage for large data objects utilizing a common
 * buffer management system.  Smaller data buffers are allocated and chained as needed.
 * All instances of DBBuffer must be immediately discarded following an undo or redo on the 
 * associated DBHandle.
 * <p>
 * The largest supported chained buffer is about 2-GBytes.  This limit may be slightly smaller 
 * based upon the underlying database buffer size.
 * <p>
 * The buffer may consist of either a single Data Node or a series of Index Nodes 
 * which reference Data Nodes.
 * <pre>
 * Data Node (Non-indexed):
 *   | 9 (1) | Obfuscation/DataLength(4) | Data ...
 * 
 * Data Node (Indexed):
 *   | 9 (1) | Data ...
 * 
 * Index Node:
 *   | 8 (1) | Obfuscation/DataLength(4) | NextIndexId(4) | DataBuffer1Id(4) | ... | DataBufferNId(4) |
 *   Number of index entries computed based upon data length and buffer size.  The index for 
 *   the entire data space is divided among a series of Index Nodes which
 *   are chained together using the NextIndexId field. Each Index Node identifies 
 *   Data Nodes which have been allocated by a DataBufferId.  A DataBufferId of -1 indicates an
 *   non-allocated data node.  The DataLength field is only used in the first index buffer.
 *   
 * Obfuscation:
 *   Data obfuscation is indicated by a '1' in the most-significant bit of the Obfuscation/DataLength 
 *   field.
 * </pre>
 * Once a DBBuffer is deleted or appended to another DBBuffer, it becomes invalid and 
 * may no longer be used.
 */
public class ChainedBuffer implements Buffer {

	// @formatter:off
	private static final byte[] XOR_MASK_BYTES = new byte[] {
		(byte)0x59, (byte)0xea, (byte)0x67, (byte)0x23, (byte)0xda, (byte)0xb8, (byte)0x00, (byte)0xb8, 
		(byte)0xc3, (byte)0x48, (byte)0xdd, (byte)0x8b, (byte)0x21, (byte)0xd6, (byte)0x94, (byte)0x78, 
		(byte)0x35, (byte)0xab, (byte)0x2b, (byte)0x7e, (byte)0xb2, (byte)0x4f, (byte)0x82, (byte)0x4e, 
		(byte)0x0e, (byte)0x16, (byte)0xc4, (byte)0x57, (byte)0x12, (byte)0x8e, (byte)0x7e, (byte)0xe6, 
		(byte)0xb6, (byte)0xbd, (byte)0x56, (byte)0x91, (byte)0x57, (byte)0x72, (byte)0xe6, (byte)0x91, 
		(byte)0xdc, (byte)0x52, (byte)0x2e, (byte)0xf2, (byte)0x1a, (byte)0xb7, (byte)0xd6, (byte)0x6f, 
		(byte)0xda, (byte)0xde, (byte)0xe8, (byte)0x48, (byte)0xb1, (byte)0xbb, (byte)0x50, (byte)0x6f, 
		(byte)0xf4, (byte)0xdd, (byte)0x11, (byte)0xee, (byte)0xf2, (byte)0x67, (byte)0xfe, (byte)0x48, 
		(byte)0x8d, (byte)0xae, (byte)0x69, (byte)0x1a, (byte)0xe0, (byte)0x26, (byte)0x8c, (byte)0x24, 
		(byte)0x8e, (byte)0x17, (byte)0x76, (byte)0x51, (byte)0xe2, (byte)0x60, (byte)0xd7, (byte)0xe6, 
		(byte)0x83, (byte)0x65, (byte)0xd5, (byte)0xf0, (byte)0x7f, (byte)0xf2, (byte)0xa0, (byte)0xd6, 
		(byte)0x4b, (byte)0xbd, (byte)0x24, (byte)0xd8, (byte)0xab, (byte)0xea, (byte)0x9e, (byte)0xa6, 
		(byte)0x48, (byte)0x94, (byte)0x3e, (byte)0x7b, (byte)0x2c, (byte)0xf4, (byte)0xce, (byte)0xdc, 
		(byte)0x69, (byte)0x11, (byte)0xf8, (byte)0x3c, (byte)0xa7, (byte)0x3f, (byte)0x5d, (byte)0x77, 
		(byte)0x94, (byte)0x3f, (byte)0xe4, (byte)0x8e, (byte)0x48, (byte)0x20, (byte)0xdb, (byte)0x56, 
		(byte)0x32, (byte)0xc1, (byte)0x87, (byte)0x01, (byte)0x2e, (byte)0xe3, (byte)0x7f, (byte)0x40,
		
	};
	// @formatter:on

	private static final int NODE_TYPE_SIZE = 1;
	private static final int DATA_LENGTH_SIZE = 4;
	private static final int ID_SIZE = 4;

	private static final int NODE_TYPE_OFFSET = 0;
	private static final int DATA_LENGTH_OFFSET = NODE_TYPE_SIZE;
	private static final int NEXT_INDEX_ID_OFFSET = DATA_LENGTH_OFFSET + DATA_LENGTH_SIZE;

	private static final int INDEX_BASE_OFFSET = NEXT_INDEX_ID_OFFSET + ID_SIZE;

	private static final int DATA_BASE_OFFSET_NONINDEXED = NODE_TYPE_SIZE + DATA_LENGTH_SIZE;
	private static final int DATA_BASE_OFFSET_INDEXED = NODE_TYPE_SIZE;

	private BufferMgr bufferMgr;
	private int size;
	private int firstBufferId;

	private byte[] xorData;
	private boolean useXORMask = false;

	private boolean readOnly = false;
	private Buffer uninitializedDataSource;
	private int uninitializedDataSourceOffset;

	private int[] indexBufferIdTable;
	private int[] dataBufferIdTable;
	private int indexesPerBuffer;

	private int dataBaseOffset;
	private int dataSpace;

	/**
	 * Construct a new chained buffer with optional obfuscation and uninitialized data source.
	 * This method may only be invoked while a database transaction 
	 * is in progress. 
	 * @param size {@literal buffer size (0 < size <= 0x7fffffff)}
	 * @param enableObfuscation true to enable xor-ing of stored data to facilitate data obfuscation.
	 * @param uninitializedDataSource optional data source for uninitialized data.  This should be a 
	 * read-only buffer which will always be used when re-instantiating the same stored ChainedBuffer.
	 * This should not be specified if buffer will be completely filled/initialized.
	 * @param unintializedDataSourceOffset uninitialized data source offset which corresponds to
	 * this buffers contents.
	 * @param bufferMgr database buffer manager
	 * @throws IOException thrown if an IO error occurs
	 */
	public ChainedBuffer(int size, boolean enableObfuscation, Buffer uninitializedDataSource,
			int unintializedDataSourceOffset, BufferMgr bufferMgr) throws IOException {
		this.bufferMgr = bufferMgr;
		this.size = size;
		this.useXORMask = enableObfuscation;

		if (size == 0) {
			throw new IllegalArgumentException("Zero length buffer not permitted");
		}
		if (size < 0) {
			throw new IllegalArgumentException(
				"Maximum bufer size is " + Integer.MAX_VALUE + "; given size of " + size);
		}

		if (uninitializedDataSource != null) {
			setUnintializedDataSource(uninitializedDataSource, unintializedDataSourceOffset);
		}

		DataBuffer firstBuffer = bufferMgr.createBuffer();
		firstBufferId = firstBuffer.getId();

		// Attempt to employ single data buffer
		dataBaseOffset = DATA_BASE_OFFSET_NONINDEXED;
		dataSpace = bufferMgr.getBufferSize() - dataBaseOffset;

		if (size <= dataSpace) {
			dataBufferIdTable = new int[] { firstBufferId };
			initializeAllocatedBuffer(0, firstBuffer);
			firstBuffer.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_DATA_NODE);
			firstBuffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			bufferMgr.releaseBuffer(firstBuffer);
		}

		// Employ index for large chained buffers
		else {
			createIndex(firstBuffer);
		}
	}

	/**
	 * Construct a new chained buffer with optional obfuscation.
	 * This method may only be invoked while a database transaction 
	 * is in progress. 
	 * @param size {@literal buffer size (0 < size <= 0x7fffffff)}
	 * @param enableObfuscation true to enable xor-ing of stored data to facilitate data obfuscation.
	 * @param bufferMgr database buffer manager
	 * @throws IOException thrown if an IO error occurs
	 */
	public ChainedBuffer(int size, boolean enableObfuscation, BufferMgr bufferMgr)
			throws IOException {
		this(size, enableObfuscation, null, 0, bufferMgr);
	}

	/**
	 * Construct a new chained buffer.
	 * This method may only be invoked while a database transaction is in progress.
	 * @param size {@literal buffer size (0 < size <= 0x7fffffff)}
	 * @param bufferMgr database buffer manager
	 * @throws IOException thrown if an IO error occurs
	 */
	public ChainedBuffer(int size, BufferMgr bufferMgr) throws IOException {
		this(size, false, null, 0, bufferMgr);
	}

	/**
	 * Construct an existing chained buffer.
	 * @param bufferMgr database buffer manager
	 * @param bufferId database buffer ID which corresponds to a stored ChainedBuffer
	 * @param uninitializedDataSource optional data source for uninitialized data.  This should be a 
	 * read-only buffer which will always be used when re-instantiating the same stored ChainedBuffer.
	 * This should not be specified if buffer will be completely filled/initialized.
	 * @param unintializedDataSourceOffset uninitialized data source offset which corresponds to
	 * this buffers contents.
	 * @throws IOException thrown if an IO error occurs
	 */
	public ChainedBuffer(BufferMgr bufferMgr, int bufferId, Buffer uninitializedDataSource,
			int unintializedDataSourceOffset) throws IOException {
		this.bufferMgr = bufferMgr;
		this.firstBufferId = bufferId;

		DataBuffer firstBuffer = bufferMgr.getBuffer(bufferId);
		size = firstBuffer.getInt(DATA_LENGTH_OFFSET);
		if (size < 0) {
			this.useXORMask = true;
			size = size & Integer.MAX_VALUE;
		}
		byte bufType = firstBuffer.getByte(NODE_TYPE_OFFSET);
		if (bufType == NodeMgr.CHAINED_BUFFER_INDEX_NODE) {
			buildIndex(firstBuffer); // releases firstBuffer
		}
		else if (bufType == NodeMgr.CHAINED_BUFFER_DATA_NODE) {
			try {
				dataBaseOffset = DATA_BASE_OFFSET_NONINDEXED;
				dataSpace = firstBuffer.length() - dataBaseOffset;
				dataBufferIdTable = new int[] { bufferId };
			}
			finally {
				bufferMgr.releaseBuffer(firstBuffer);
			}
		}
		else {
			throw new IOException("Invalid Buffer");
		}

		if (uninitializedDataSource != null) {
			setUnintializedDataSource(uninitializedDataSource, unintializedDataSourceOffset);
		}
	}

	/**
	 * Construct an existing chained buffer.
	 * @param bufferMgr database buffer manager
	 * @param bufferId database buffer ID which corresponds to a stored ChainedBuffer
	 * @throws IOException thrown if an IO error occurs
	 */
	public ChainedBuffer(BufferMgr bufferMgr, int bufferId) throws IOException {
		this(bufferMgr, bufferId, null, 0);
	}

	private int getObfuscationDataLengthFieldValue() {
		// most-significant bit of DataLength field indicates use of obfuscation
		return size | (useXORMask ? Integer.MIN_VALUE : 0);
	}

	/**
	 * Generate the XOR'd value for the specified byteValue which is located at the
	 * specified bufferOffset.
	 * @param bufferOffset offset within a single chained buffer, valid values are in the 
	 * range 0 to (dataSpace-1).  This value is used to determine the appropriate XOR mask.
	 * @param byteValue value to be XOR'd against appropriate mask value
	 * @return XOR'd value
	 */
	private byte xorMaskByte(int bufferOffset, byte byteValue) {
		byte maskByte = XOR_MASK_BYTES[bufferOffset % XOR_MASK_BYTES.length];
		return (byte) (byteValue ^ maskByte);
	}

	/**
	 * Get an XOR obfuscation mask of the specified length in support of the 
	 * short, int and long get/put methods.
	 * @param bufferOffset offset within a single chained buffer, valid values are in the 
	 * range 0 to (dataSpace-1).  The value (bufferOffset+len-1) must be less than dataSpace.
	 * @param len mask length (2, 4, or 8)
	 * @return XOR mask of specified length which corresponds to specified bufferOffset.
	 */
	private long getXorMask(int bufferOffset, int len) {
		long mask = 0;
		for (int i = 0; i < len; i++) {
			mask = (mask << 8) | ((long) xorMaskByte(bufferOffset++, (byte) 0) & 0xff);
		}
		return mask;
	}

	/**
	 * If this chained buffer was not completely filled/initialized a dataSource may be used
	 * obtain the initial values when needed.  When an uninitialized area is written, any unwritten
	 * areas within the containing block(s) will be initialized from the uninitialized dataSource.
	 * The same uninitialized read-only dataSource used for a chained buffer should be re-applied
	 * anytime this chained buffer is re-instantiated. 
	 * 
	 * @param dataSource data source for unitilized bytes
	 * @param dataSourceOffset offset within dataSource which corresponds to first byte of
	 * this chained buffer.
	 */
	private void setUnintializedDataSource(Buffer dataSource, int dataSourceOffset) {

		if (dataSourceOffset < 0) {
			throw new IllegalArgumentException("Invalid data source offset: " + dataSourceOffset);
		}

		int maxOffset = dataSourceOffset - 1 + size;
		if (maxOffset < 0 || maxOffset >= dataSource.length()) {
			throw new IllegalArgumentException("Data source has insufficient bytes (need " + size +
				" bytes at offset " + dataSourceOffset);
		}

		this.uninitializedDataSource = dataSource;
		this.uninitializedDataSourceOffset = dataSourceOffset;
	}

	/**
	 * @return true if obfuscated data storage has been enabled
	 */
	public boolean hasObfuscatedStorage() {
		return useXORMask;
	}

	/**
	 * Set the read-only state of this ChainedBuffer.  After invoking this method any
	 * attempt to alter this buffer will result in an UnsupportedOperation exception.
	 */
	public void setReadOnly() {
		this.readOnly = true;
	}

	/**
	 * Return the maximum number of buffers consumed by the storage of this DBBuffer object.
	 * The actual number may be less if data has not been written to the entire buffer.
	 * @return total number of buffers consumed by this ChaninedBuffer.
	 */
	int getBufferCount() {
		return dataBufferIdTable.length +
			(indexBufferIdTable != null ? indexBufferIdTable.length : 0);
	}

	/**
	 * Set the new size for this DBBuffer object.
	 * @param size new size
	 * @param preserveData if true, existing data is preserved at the original offsets.  If false,
	 * no additional effort will be expended to preserve data.
	 * @throws UnsupportedOperationException thrown if this ChainedBuffer utilizes an 
	 * Uninitialized Data Source or is read-only
	 * @throws IOException thrown if an IO error occurs.
	 * @throws UnsupportedOperationException if read-only or uninitialized data source is used
	 */
	public synchronized void setSize(int size, boolean preserveData) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (uninitializedDataSource != null) {
			throw new UnsupportedOperationException(
				"Buffer size may not be changed when using unintialized data source");
		}
		if (dataBufferIdTable == null) {
			throw new AssertException("Invalid Buffer");
		}
		if (size > this.size) {
			grow(size, preserveData);
		}
		else {
			shrink(size, preserveData);
		}
	}

	/**
	 * Increase the size of this DBBuffer object.
	 * @param newSize new size.
	 * @param preserveData if true, existing data is preserved at the original offsets.  If false,
	 * no additional effort will be expended to preserve data.
	 * @throws IOException thrown if an IO error occurs.
	 */
	private void grow(int newSize, boolean preserveData) throws IOException {

		int oldSize = this.size;
		this.size = newSize;

		// Currently using a single data buffer
		if (dataBufferIdTable.length == 1) {

			// Transition to an indexed chained buffer
			if (newSize > dataSpace) {

				DataBuffer firstBuffer = bufferMgr.getBuffer(firstBufferId);
				DataBuffer newFirstDataBuf = null;

				try {
					// Save data in new data buffer
					if (preserveData) {
						newFirstDataBuf = bufferMgr.createBuffer();
						newFirstDataBuf.copy(DATA_BASE_OFFSET_INDEXED, firstBuffer,
							DATA_BASE_OFFSET_NONINDEXED, oldSize);

						int indexedDataSpace = newFirstDataBuf.length() - DATA_BASE_OFFSET_INDEXED;
						byte[] zeroBytes = new byte[indexedDataSpace - oldSize];
						if (useXORMask) {
							int offset = oldSize;
							for (int i = 0; i < zeroBytes.length; i++, offset++) {
								zeroBytes[i] = xorMaskByte(offset, zeroBytes[i]);
							}
						}
						newFirstDataBuf.put(DATA_BASE_OFFSET_INDEXED + oldSize, zeroBytes);
					}

					// Establish index for DBBuffer
					createIndex(firstBuffer);
					firstBuffer = null;

					// Establish first data buffer
					if (preserveData) {
						addBuffer(0, newFirstDataBuf);
					}
				}
				finally {
					if (firstBuffer != null) {
						bufferMgr.releaseBuffer(firstBuffer);
					}
					if (newFirstDataBuf != null) {
						bufferMgr.releaseBuffer(newFirstDataBuf);
					}
				}

				return;
			}

			// Adjust stored buffer size
			DataBuffer buffer = bufferMgr.getBuffer(firstBufferId);
			buffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			bufferMgr.releaseBuffer(buffer);
		}

		// Already using an index - existing data is always preserved
		else {
			byte[] emptyIndexData = new byte[indexesPerBuffer * ID_SIZE];
			Arrays.fill(emptyIndexData, (byte) 0xff);

			// Compute index counts
			int newIndexCount = ((newSize - 1) / dataSpace) + 1;
			int newIndexBufferCount = ((newIndexCount - 1) / indexesPerBuffer) + 1;

			// Grow dataBufferIdTable
			int[] newDataBufferIdTable = new int[newIndexCount];
			System.arraycopy(dataBufferIdTable, 0, newDataBufferIdTable, 0,
				dataBufferIdTable.length);
			Arrays.fill(newDataBufferIdTable, dataBufferIdTable.length, newIndexCount, -1);
			dataBufferIdTable = newDataBufferIdTable;

			// Grow indexBufferIdTable
			int oldIndexBufferCount = indexBufferIdTable.length;
			if (oldIndexBufferCount < newIndexBufferCount) {

				int[] newIndexBufferIdTable = new int[newIndexBufferCount];
				System.arraycopy(indexBufferIdTable, 0, newIndexBufferIdTable, 0,
					oldIndexBufferCount);
				Arrays.fill(newIndexBufferIdTable, oldIndexBufferCount, newIndexBufferCount, -1);
				indexBufferIdTable = newIndexBufferIdTable;

				// Allocate additional index buffers
				DataBuffer indexBuffer =
					bufferMgr.getBuffer(indexBufferIdTable[oldIndexBufferCount - 1]);
				for (int i = oldIndexBufferCount; i < newIndexBufferCount; i++) {
					indexBuffer = appendIndexBuffer(indexBuffer);
					indexBuffer.put(INDEX_BASE_OFFSET, emptyIndexData);  // initialize to all -1's
					indexBufferIdTable[i] = indexBuffer.getId();
				}
				bufferMgr.releaseBuffer(indexBuffer);
			}

			// Adjust stored buffer size
			DataBuffer buffer = bufferMgr.getBuffer(firstBufferId);
			buffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			bufferMgr.releaseBuffer(buffer);
		}

	}

	/**
	 * Attempt to shrink this DBBuffer object into a single data buffer.
	 * The current <code>size</code> field reflects the new small size.
	 * @param preserveData if true, existing data is preserved at the original offsets.  If false,
	 * no additional effort will be expended to preserve data.
	 * @return true if successful, false if too big for single buffer.
	 * @throws IOException thrown if an IO error occurs.
	 */
	private boolean shrinkToSingleBuffer(boolean preserveData) throws IOException {

		int singleDataSpace = bufferMgr.getBufferSize() - DATA_BASE_OFFSET_NONINDEXED;
		if (size > singleDataSpace) {
			return false;
		}

		// Convert first index buffer to a data buffer
		DataBuffer firstBuffer = bufferMgr.getBuffer(firstBufferId);
		DataBuffer oldFirstDataBuf = null;
		try {
			firstBuffer.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_DATA_NODE);
			firstBuffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());

			if (preserveData && dataBufferIdTable[0] >= 0) {
				oldFirstDataBuf = bufferMgr.getBuffer(dataBufferIdTable[0]);
				firstBuffer.copy(DATA_BASE_OFFSET_NONINDEXED, oldFirstDataBuf,
					DATA_BASE_OFFSET_INDEXED, size);
			}
		}
		finally {
			bufferMgr.releaseBuffer(firstBuffer);
			if (oldFirstDataBuf != null) {
				bufferMgr.releaseBuffer(oldFirstDataBuf);
			}
		}

		// Remove all data buffers
		for (int element : dataBufferIdTable) {
			if (element >= 0) {
				bufferMgr.deleteBuffer(element);
			}
		}

		// Remove all, except the first, index buffers
		for (int i = 1; i < indexBufferIdTable.length; i++) {
			bufferMgr.deleteBuffer(indexBufferIdTable[i]);
		}

		// Update buffer offsets, sizes and elliminate index
		dataBaseOffset = DATA_BASE_OFFSET_NONINDEXED;
		dataSpace = singleDataSpace;
		dataBufferIdTable = new int[1];
		dataBufferIdTable[0] = firstBufferId;
		indexBufferIdTable = null;
		return true;
	}

	/**
	 * Decrease the size of this DBBuffer object.
	 * @param newSize new size.
	 * @param preserveData if true, existing data is preserved at the original offsets.  If false,
	 * no additional effort will be expended to preserve data.
	 * @throws IOException thrown if IO error occurs
	 */
	private void shrink(int newSize, boolean preserveData) throws IOException {

		this.size = newSize;

		// Currently using a single data buffer - data is always preserved
		if (dataBufferIdTable.length == 1) {
			DataBuffer buffer = bufferMgr.getBuffer(firstBufferId);
			buffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			bufferMgr.releaseBuffer(buffer);
		}

		// Already using an index
		else if (!shrinkToSingleBuffer(preserveData)) {

			// Compute index counts
			int newIndexCount = ((newSize - 1) / dataSpace) + 1;
			int newIndexBufferCount = ((newIndexCount - 1) / indexesPerBuffer) + 1;

			// Delete extra data buffers
			int oldIndexCount = dataBufferIdTable.length;
			for (int i = newIndexCount; i < oldIndexCount; i++) {
				if (dataBufferIdTable[i] >= 0) {
					bufferMgr.deleteBuffer(dataBufferIdTable[i]);
				}
			}

			// Shrink dataBufferIdTable
			int[] newDataBufferIdTable = new int[newIndexCount];
			System.arraycopy(dataBufferIdTable, 0, newDataBufferIdTable, 0,
				newDataBufferIdTable.length);
			dataBufferIdTable = newDataBufferIdTable;

			// Shrink indexBufferIdTable
			int oldIndexBufferCount = indexBufferIdTable.length;
			if (oldIndexBufferCount > newIndexBufferCount) {

				// Delete extra index and data buffers
				for (int i = newIndexBufferCount; i < oldIndexBufferCount; i++) {
					bufferMgr.deleteBuffer(indexBufferIdTable[i]);
				}

				int[] newIndexBufferIdTable = new int[newIndexBufferCount];
				System.arraycopy(indexBufferIdTable, 0, newIndexBufferIdTable, 0,
					newIndexBufferCount);
				indexBufferIdTable = newIndexBufferIdTable;
			}

			// Adjust stored buffer size
			DataBuffer buffer = bufferMgr.getBuffer(firstBufferId);
			buffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			bufferMgr.releaseBuffer(buffer);
		}
	}

	/**
	 * Split this DBBuffer object into two separate DBBuffers.  This DBBuffer remains
	 * valid but its new size is equal offset.  The newly created DBBuffer is 
	 * returned.
	 * @param offset the split point.  The byte at this offset becomes the first
	 * byte within the new buffer.
	 * @return the new DBBuffer object.
	 * @throws UnsupportedOperationException thrown if this ChainedBuffer is read-only
	 * @throws ArrayIndexOutOfBoundsException if offset is invalid.
	 * @throws IOException thrown if an IO error occurs
	 */
	public synchronized ChainedBuffer split(int offset) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (firstBufferId < 0) {
			throw new AssertException("Invalid Buffer");
		}
		if (offset < 0 || offset >= size) {
			throw new ArrayIndexOutOfBoundsException();
		}

		// Create new DBBuffer
		int cnt = size - offset;
		ChainedBuffer newDBBuf = new ChainedBuffer(cnt, useXORMask, uninitializedDataSource,
			uninitializedDataSourceOffset + offset, bufferMgr);

		// Copy data from this DBBuffer into new DBBuffer
		int newOffset = 0;
		byte[] data = new byte[dataSpace];
		int bufferDataOffset = offset % dataSpace;
		int dataSize = dataSpace - bufferDataOffset;
		for (int index = offset / dataSpace; index < dataBufferIdTable.length; ++index) {
			if (cnt < dataSize) {
				dataSize = cnt;
			}
			if (dataBufferIdTable[index] >= 0) {

				DataBuffer dataBuf = bufferMgr.getBuffer(dataBufferIdTable[index]);
				try {
					dataBuf.get(bufferDataOffset + dataBaseOffset, data, 0, dataSize);
					if (useXORMask) {
						for (int i = 0; i < dataSize; i++) {
							data[i] = xorMaskByte(bufferDataOffset + i, data[i]);
						}
					}
					newDBBuf.put(newOffset, data, 0, dataSize);
				}
				finally {
					bufferMgr.releaseBuffer(dataBuf);
				}

				// Delete original data buffer if all data was copied
				if (bufferDataOffset == 0) {
					bufferMgr.deleteBuffer(dataBufferIdTable[index]);
					dataBufferIdTable[index] = -1;
				}
			}
			cnt -= dataSize;
			newOffset += dataSize;
			bufferDataOffset = 0;
			dataSize = data.length;
		}

		// Resize this buffer
		shrink(offset, true);

		return newDBBuf;
	}

	/**
	 * Append the contents of the specified dbBuf onto the end of this buffer.
	 * The size of this buffer increases by the size of dbBuf.  When the operation 
	 * is complete, dbBuf object is no longer valid and must not be used.
	 * @param dbBuf the buffer to be appended to this buffer.
	 * @throws IOException thrown if an IO error occurs
	 * @throws UnsupportedOperationException if read-only, uninitialized data source is used,
	 * or both buffers do not have the same obfuscation enablement
	 */
	public synchronized void append(ChainedBuffer dbBuf) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (uninitializedDataSource != null) {
			throw new UnsupportedOperationException(
				"Buffer size may not be changed when using unintialized data source");
		}
		if (firstBufferId < 0) {
			throw new AssertException("Invalid Buffer");
		}
		if (dbBuf.firstBufferId < 0 || firstBufferId == dbBuf.firstBufferId) {
			throw new IllegalArgumentException("Illegal DBBuffer argument");
		}

		// Grow this buffer - preserve data	
		int offset = size;
		int newSize = size + dbBuf.size;
		grow(newSize, true);

		// Delete dbBuf index buffers
		BufferMgr otherBufMgr = dbBuf.bufferMgr;
		if (dbBuf.indexBufferIdTable != null) {
			for (int element : dbBuf.indexBufferIdTable) {
				otherBufMgr.deleteBuffer(element);
			}
		}
		dbBuf.indexBufferIdTable = null;
		dbBuf.firstBufferId = -1;

		// Copy dbBuf data and delete original buffer
		int cnt = 0;
		int dataSize = dbBuf.dataSpace;
		byte[] data = new byte[dataSize];

		for (int element : dbBuf.dataBufferIdTable) {
			cnt += dataSize;
			if (cnt > dbBuf.size) {
				dataSize -= (cnt - dbBuf.size);
			}
			if (element >= 0) {

				DataBuffer otherDataBuf = otherBufMgr.getBuffer(element);
				try {
					otherDataBuf.get(dbBuf.dataBaseOffset, data, 0, dataSize);
					if (dbBuf.useXORMask) {
						for (int n = 0; n < dataSize; n++) {
							data[n] = xorMaskByte(n, data[n]);
						}
					}
					put(offset, data, 0, dataSize);
				}
				finally {
					otherBufMgr.releaseBuffer(otherDataBuf);
				}

				// Delete dbBuf data buffer
				otherBufMgr.deleteBuffer(element);
			}
			offset += dataSize;
		}

		dbBuf.dataBufferIdTable = null;
		dbBuf.size = 0;
	}

	/**
	 * Append a new initialized index buffer to the index buffer provided.
	 * The index buffer provided is always released.
	 * @param indexBuffer the last index buffer.
	 * @return DataBuffer
	 * @throws IOException thrown if an IO error occurs
	 */
	private DataBuffer appendIndexBuffer(DataBuffer indexBuffer) throws IOException {
		try {
			DataBuffer nextBuf = bufferMgr.createBuffer();
			nextBuf.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_INDEX_NODE);
			nextBuf.putInt(DATA_LENGTH_OFFSET, -1);  // only used in first buffer
			nextBuf.putInt(NEXT_INDEX_ID_OFFSET, -1);
			indexBuffer.putInt(NEXT_INDEX_ID_OFFSET, nextBuf.getId());
			return nextBuf;
		}
		finally {
			bufferMgr.releaseBuffer(indexBuffer);
		}
	}

	/**
	 * Allocate in-memory index and compute buffer parameters for index mode.
	 * @param buffer sample buffer for computing data and index parameters.
	 * @return number of index entries
	 */
	private int allocateIndex(DataBuffer buffer) {
		dataBaseOffset = DATA_BASE_OFFSET_INDEXED;
		dataSpace = buffer.length() - dataBaseOffset;
		int indexCount = ((size - 1) / dataSpace) + 1;
		indexesPerBuffer = (buffer.length() - INDEX_BASE_OFFSET) / ID_SIZE;
		dataBufferIdTable = new int[indexCount];
		return indexCount;
	}

	/**
	 * Create and initialize a new index for this DBBuffer.
	 * The entire index is allocated within the database (i.e., Index Nodes).  
	 * Data Nodes are only allocated as needed when data is written.
	 * @param indexBuffer first index buffer.  This buffer will be released
	 * prior to returning.
	 * @throws IOException thrown if IO error occurs
	 */
	private void createIndex(DataBuffer indexBuffer) throws IOException {

		try {
			indexBuffer.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_INDEX_NODE);
			indexBuffer.putInt(DATA_LENGTH_OFFSET, getObfuscationDataLengthFieldValue());
			indexBuffer.putInt(NEXT_INDEX_ID_OFFSET, -1);

			int indexCount = allocateIndex(indexBuffer);
			Arrays.fill(dataBufferIdTable, -1);
			int indexBufferCount = ((indexCount - 1) / indexesPerBuffer) + 1;
			indexBufferIdTable = new int[indexBufferCount];

			byte[] emptyIndexData = new byte[indexesPerBuffer * ID_SIZE];
			Arrays.fill(emptyIndexData, (byte) 0xff);

			indexBufferIdTable[0] = indexBuffer.getId();
			indexBuffer.put(INDEX_BASE_OFFSET, emptyIndexData);
			for (int i = 1; i < indexBufferCount; i++) {
				indexBuffer = appendIndexBuffer(indexBuffer);
				indexBufferIdTable[i] = indexBuffer.getId();
				indexBuffer.put(INDEX_BASE_OFFSET, emptyIndexData);
			}
		}
		finally {
			bufferMgr.releaseBuffer(indexBuffer);
		}
	}

	/**
	 * Build the in-memory index for a previously stored DBBuffer.
	 * @param indexBuffer first index buffer.  This buffer will be released
	 * prior to returning.
	 * @throws IOException thrown if IO error occurs
	 */
	private void buildIndex(DataBuffer indexBuffer) throws IOException {

		int indexCount = allocateIndex(indexBuffer);
		int indexBufferCount = ((indexCount - 1) / indexesPerBuffer) + 1;
		indexBufferIdTable = new int[indexBufferCount];

		try {
			int index = 0;
			indexBufferIdTable[index] = indexBuffer.getId();
			int ix = 0;
			int offset = INDEX_BASE_OFFSET;
			for (int i = 0; i < indexCount; i++) {

				// Advance to next index buffer if needed
				if (ix == indexesPerBuffer) {
					int nextId = indexBuffer.getInt(NEXT_INDEX_ID_OFFSET);
					if (nextId < 0) {
						throw new AssertException();
					}
					bufferMgr.releaseBuffer(indexBuffer);
					indexBuffer = bufferMgr.getBuffer(nextId);
					indexBufferIdTable[++index] = indexBuffer.getId();
					ix = 0;
					offset = INDEX_BASE_OFFSET;
				}

				// Fetch next index buffer ID
				dataBufferIdTable[i] = indexBuffer.getInt(offset);
				offset += ID_SIZE;
				++ix;
			}
		}
		finally {
			bufferMgr.releaseBuffer(indexBuffer);
		}
	}

	/**
	 * Get the first buffer ID associated with this chained buffer.  This DBBuffer
	 * may be reinstatiated using the returned buffer ID provided subsequent changes 
	 * are not made.
	 * @return buffer ID
	 */
	@Override
	public int getId() {
		return firstBufferId;
	}

	/**
	 * Delete and release all underlying DataBuffers. 
	 * @throws IOException thrown if an IO error occurs
	 */
	public synchronized void delete() throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (firstBufferId < 0) {
			throw new AssertException("Invalid Buffer");
		}

		// Remove all data buffers
		for (int element : dataBufferIdTable) {
			if (element >= 0) {
				bufferMgr.deleteBuffer(element);
			}
		}
		dataBufferIdTable = null;

		// Remove all, except the first, index buffers
		if (indexBufferIdTable != null) {
			for (int element : indexBufferIdTable) {
				bufferMgr.deleteBuffer(element);
			}
		}
		indexBufferIdTable = null;
		size = 0;
		firstBufferId = -1;
	}

	/**
	 * Get byte data from the specified chained buffer.
	 * @param offset ChainedBuffer offset (needed for uninitialized buffer pass-through)
	 * @param index buffer index within chain
	 * @param bufferDataOffset data offset within specified buffer
	 * @param data destination byte array
	 * @param dataOffset destination array offset within data
	 * @param length number of bytes to read
	 * @return int actual number of byte read.
	 * This could be smaller than length if the end of buffer is 
	 * encountered while reading data.
	 * @throws IOException thrown if IO error occurs
	 */
	private int getBytes(int offset, int index, int bufferDataOffset, byte[] data, int dataOffset,
			int length) throws IOException {
		int availableData = dataSpace - bufferDataOffset;
		int len = availableData < length ? availableData : length;
		int id = dataBufferIdTable[index];
		if (id < 0) {
			if (uninitializedDataSource != null) {
				uninitializedDataSource.get(uninitializedDataSourceOffset + offset, data,
					dataOffset, len);
			}
			else {
				Arrays.fill(data, dataOffset, dataOffset + len, (byte) 0);
			}
		}
		else {
			DataBuffer buffer = bufferMgr.getBuffer(id);
			buffer.get(dataBaseOffset + bufferDataOffset, data, dataOffset, len);
			bufferMgr.releaseBuffer(buffer);
			if (useXORMask) {
				int dataIndex = dataOffset;
				for (int i = 0; i < len; i++, dataIndex++) {
					data[dataIndex] = xorMaskByte(bufferDataOffset++, data[dataIndex]);
				}
			}
		}
		return len;
	}

	/*
	 * @see ghidra.framework.store.Buffer#get(int, byte[], int, int)
	 */
	@Override
	public synchronized void get(int offset, byte[] data, int dataOffset, int length)
			throws IOException {
		if (dataBufferIdTable == null) {
			throw new AssertException("Invalid Buffer");
		}
		if (offset < 0 || (offset + length - 1) >= size) {
			throw new ArrayIndexOutOfBoundsException();
		}
		if (data.length < dataOffset + length) {
			throw new ArrayIndexOutOfBoundsException();
		}
		int index = offset / dataSpace;
		int bufferDataOffset = offset % dataSpace;
		int len = length;
		while (len > 0) {
			int n = getBytes(offset, index++, bufferDataOffset, data, dataOffset, len);
			dataOffset += n;
			offset += n;
			len -= n;
			bufferDataOffset = 0;
		}
	}

	/*
	 * @see ghidra.framework.store.Buffer#get(int, byte[])
	 */
	@Override
	public synchronized void get(int offset, byte[] data) throws IOException {
		get(offset, data, 0, data.length);
	}

	/*
	 * @see ghidra.framework.store.Buffer#get(int, int)
	 */
	@Override
	public synchronized byte[] get(int offset, int length) throws IOException {
		byte[] data = new byte[length];
		get(offset, data, 0, length);
		return data;
	}

	/*
	 * @see ghidra.framework.store.Buffer#getByte(int)
	 */
	@Override
	public synchronized byte getByte(int offset) throws IOException {
		if (dataBufferIdTable == null) {
			throw new AssertException("Invalid Buffer");
		}
		if (offset < 0 || offset >= size) {
			throw new ArrayIndexOutOfBoundsException();
		}
		int index = offset / dataSpace;
		int bufferDataOffset = offset % dataSpace;
		int id = dataBufferIdTable[index];
		if (id < 0) {
			if (uninitializedDataSource != null) {
				return uninitializedDataSource.getByte(uninitializedDataSourceOffset + offset);
			}
			return 0;
		}
		DataBuffer buffer = bufferMgr.getBuffer(id);
		byte b = buffer.getByte(dataBaseOffset + bufferDataOffset);
		bufferMgr.releaseBuffer(buffer);
		if (useXORMask) {
			b = xorMaskByte(bufferDataOffset, b);
		}
		return b;
	}

	/*
	 * @see ghidra.framework.store.Buffer#getInt(int)
	 */
	@Override
	public synchronized int getInt(int offset) throws IOException {
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 3 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 3) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			int index = offset / dataSpace;
			int id = dataBufferIdTable[index];
			if (id < 0) {
				if (uninitializedDataSource != null) {
					return uninitializedDataSource.getInt(uninitializedDataSourceOffset + offset);
				}
				return 0;
			}
			DataBuffer buffer = bufferMgr.getBuffer(id);
			int value = buffer.getInt(bufferOffset);
			bufferMgr.releaseBuffer(buffer);
			if (useXORMask) {
				value = value ^ (int) getXorMask(offset % dataSpace, 4);
			}
			return value;
		}
		byte[] data = get(offset, 4);
		return ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) | ((data[2] & 0xff) << 8) |
			(data[3] & 0xff);
	}

	/*
	 * @see ghidra.framework.store.Buffer#getLong(int)
	 */
	@Override
	public synchronized long getLong(int offset) throws IOException {
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 7 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 7) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			int index = offset / dataSpace;
			int id = dataBufferIdTable[index];
			if (id < 0) {
				if (uninitializedDataSource != null) {
					return uninitializedDataSource.getLong(uninitializedDataSourceOffset + offset);
				}
				return 0;
			}
			DataBuffer buffer = bufferMgr.getBuffer(id);
			long value = buffer.getLong(bufferOffset);
			bufferMgr.releaseBuffer(buffer);
			if (useXORMask) {
				value = value ^ getXorMask(offset % dataSpace, 8);
			}
			return value;
		}
		byte[] data = get(offset, 8);
		return (((long) data[0] & 0xff) << 56) | (((long) data[1] & 0xff) << 48) |
			(((long) data[2] & 0xff) << 40) | (((long) data[3] & 0xff) << 32) |
			(((long) data[4] & 0xff) << 24) | (((long) data[5] & 0xff) << 16) |
			(((long) data[6] & 0xff) << 8) | ((long) data[7] & 0xff);
	}

	/*
	 * @see ghidra.framework.store.Buffer#getShort(int)
	 */
	@Override
	public synchronized short getShort(int offset) throws IOException {
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 1 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 1) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			int index = offset / dataSpace;
			int id = dataBufferIdTable[index];
			if (id < 0) {
				if (uninitializedDataSource != null) {
					return uninitializedDataSource.getShort(uninitializedDataSourceOffset + offset);
				}
				return 0;
			}
			DataBuffer buffer = bufferMgr.getBuffer(id);
			short value = buffer.getShort(bufferOffset);
			bufferMgr.releaseBuffer(buffer);
			if (useXORMask) {
				value = (short) (value ^ (int) getXorMask(offset % dataSpace, 2));
			}
			return value;
		}
		byte[] data = get(offset, 2);
		return (short) (((data[0] & 0xff) << 8) | (data[1] & 0xff));
	}

	/*
	 * @see ghidra.framework.store.Buffer#length()
	 */
	@Override
	public int length() {
		return size;
	}

	/**
	 * Fill the buffer over the specified range with a byte value.
	 * @param startOffset starting offset, inclusive
	 * @param endOffset ending offset, exclusive
	 * @param fillByte byte value
	 * @throws IOException thrown if an IO error occurs
	 */
	public synchronized void fill(int startOffset, int endOffset, byte fillByte)
			throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (endOffset <= startOffset) {
			throw new IllegalArgumentException();
		}
		if (startOffset < 0 || endOffset > size) {
			throw new ArrayIndexOutOfBoundsException();
		}
		byte[] fillData = new byte[dataSpace];
		Arrays.fill(fillData, fillByte);
		int index = startOffset / dataSpace;
		int bufferDataOffset = startOffset % dataSpace;
		int len = endOffset - startOffset + 1;

		if (useXORMask) {
			xorData = new byte[dataSpace];
		}
		try {
			while (len > 0) {
				int n = putBytes(index++, bufferDataOffset, fillData, 0, len);
				len -= n;
				bufferDataOffset = 0;
			}
		}
		finally {
			xorData = null;
		}
	}

	/**
	 * Put data into the specified chained buffer.  
	 * NOTE: The caller of this method is responsible for allocating the xorData byte array
	 * used for applying the obfuscation XOR mask.
	 * @param index index of within buffer chain
	 * @param bufferDataOffset data buffer offset
	 * @param data source byte array
	 * @param dataOffset source array offset within data
	 * @param length number of bytes to write
	 * @return int actual number of bytes written.  
	 * This could be smaller than length if the end of buffer is 
	 * encountered while writing data.
	 * @throws IOException thrown if an IO error occurs
	 */
	private int putBytes(int index, int bufferDataOffset, byte[] data, int dataOffset, int length)
			throws IOException {
		int availableSpace = dataSpace - bufferDataOffset;
		int len = availableSpace < length ? availableSpace : length;
		if (xorData != null) {
			int offset = bufferDataOffset;
			int dataIndex = dataOffset;
			for (int i = 0; i < len; i++, dataIndex++, offset++) {
				xorData[i] = xorMaskByte(offset, data[dataIndex]);
			}
			data = xorData;
			dataOffset = 0;
		}
		DataBuffer buffer = getBuffer(index);
		buffer.put(bufferDataOffset + dataBaseOffset, data, dataOffset, len);
		bufferMgr.releaseBuffer(buffer);
		return len;
	}

	/**
	 * Fill buffer with data provided by InputStream.  If 
	 * stream is exhausted, the remainder of the buffer will be filled
	 * with 0's.
	 * @param in data source
	 * @throws IOException thrown if IO error occurs.
	 */
	public synchronized void fill(InputStream in) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		byte[] data = new byte[dataSpace];
		int index = 0;
		int offset = 0;
		int length = size;
		int readSpace = dataSpace;

		if (useXORMask) {
			xorData = new byte[dataSpace];
		}
		try {
			while (length > 0) {
				int readLen = Math.min(length, readSpace);
				int cnt = in.read(data, 0, readLen);
				if (cnt < 0) {
					break;
				}

				putBytes(index, offset, data, 0, readLen);

				readSpace -= cnt;
				offset += cnt;
				length -= cnt;

				if (readSpace == 0) {
					// move-on to next buffer
					++index;
					readSpace = dataSpace;
					offset = 0;
				}

			}
		}
		finally {
			xorData = null;
		}
	}

	/*
	 * @see ghidra.framework.store.Buffer#put(int, byte[], int, int)
	 */
	@Override
	public synchronized int put(int offset, byte[] data, int dataOffset, int length)
			throws IOException {

		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (dataBufferIdTable == null) {
			throw new AssertException("Invalid Buffer");
		}
		if (offset < 0 || (offset + length - 1) >= size) {
			throw new ArrayIndexOutOfBoundsException();
		}
		int index = offset / dataSpace;
		int bufferDataOffset = offset % dataSpace;
		int len = length;

		if (useXORMask) {
			xorData = new byte[dataSpace];
		}
		try {
			while (len > 0) {
				int n = putBytes(index++, bufferDataOffset, data, dataOffset, len);
				dataOffset += n;
				len -= n;
				bufferDataOffset = 0;
			}
			return offset + length;
		}
		finally {
			xorData = null;
		}
	}

	/*
	 * @see ghidra.framework.store.Buffer#put(int, byte[])
	 */
	@Override
	public synchronized int put(int offset, byte[] bytes) throws IOException {
		return put(offset, bytes, 0, bytes.length);
	}

	/*
	 * @see ghidra.framework.store.Buffer#putByte(int, byte)
	 */
	@Override
	public synchronized int putByte(int offset, byte b) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		if (dataBufferIdTable == null) {
			throw new AssertException("Invalid Buffer");
		}
		if (offset < 0 || offset >= size) {
			throw new ArrayIndexOutOfBoundsException();
		}
		DataBuffer buffer = getBuffer(offset / dataSpace);
		int bufferDataOffset = offset % dataSpace;
		if (useXORMask) {
			b = xorMaskByte(bufferDataOffset, b);
		}
		buffer.putByte(dataBaseOffset + bufferDataOffset, b);
		bufferMgr.releaseBuffer(buffer);
		return offset + 1;
	}

	/*
	 * @see ghidra.framework.store.Buffer#putInt(int, int)
	 */
	@Override
	public synchronized int putInt(int offset, int v) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 3 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 3) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			if (useXORMask) {
				v = v ^ (int) getXorMask(offset % dataSpace, 4);
			}
			DataBuffer buffer = getBuffer(offset / dataSpace);
			buffer.putInt(bufferOffset, v);
			bufferMgr.releaseBuffer(buffer);
		}
		else {
			byte[] data = new byte[4];
			data[0] = (byte) (v >> 24);
			data[1] = (byte) (v >> 16);
			data[2] = (byte) (v >> 8);
			data[3] = (byte) v;
			put(offset, data);
		}
		return offset + 4;
	}

	/*
	 * @see ghidra.framework.store.Buffer#putLong(int, long)
	 */
	@Override
	public synchronized int putLong(int offset, long v) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 7 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 7) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			if (useXORMask) {
				v = v ^ getXorMask(offset % dataSpace, 8);
			}
			DataBuffer buffer = getBuffer(offset / dataSpace);
			buffer.putLong(bufferOffset, v);
			bufferMgr.releaseBuffer(buffer);
		}
		else {
			byte[] data = new byte[8];
			data[0] = (byte) (v >> 56);
			data[1] = (byte) (v >> 48);
			data[2] = (byte) (v >> 40);
			data[3] = (byte) (v >> 32);
			data[4] = (byte) (v >> 24);
			data[5] = (byte) (v >> 16);
			data[6] = (byte) (v >> 8);
			data[7] = (byte) v;
			put(offset, data);
		}
		return offset + 8;
	}

	@Override
	public synchronized int putShort(int offset, short v) throws IOException {
		if (readOnly) {
			throw new UnsupportedOperationException("Read-only buffer");
		}
		int bufferOffset = dataBaseOffset + (offset % dataSpace);
		if (bufferOffset + 1 <= dataSpace) {
			if (dataBufferIdTable == null) {
				throw new AssertException("Invalid Buffer");
			}
			if (offset < 0 || (offset + 1) >= size) {
				throw new ArrayIndexOutOfBoundsException();
			}
			if (useXORMask) {
				v = (short) (v ^ (short) getXorMask(offset % dataSpace, 2));
			}
			DataBuffer buffer = getBuffer(offset / dataSpace);
			buffer.putShort(bufferOffset, v);
			bufferMgr.releaseBuffer(buffer);
		}
		else {
			byte[] data = new byte[2];
			data[0] = (byte) (v >> 8);
			data[1] = (byte) v;
			put(offset, data);
		}
		return offset + 2;
	}

	/**
	 * Get a data buffer.
	 * @param index index of within buffer chain
	 * @return requested data buffer.
	 * @throws IOException thrown if an IO error occurs
	 */
	private DataBuffer getBuffer(int index) throws IOException {
		// if databufferIdTable is null, index must be null.  let it throw null pointer in this case.
		int bufferId =
			(dataBufferIdTable == null && index == 0) ? firstBufferId : dataBufferIdTable[index];
		if (bufferId < 0) {
			DataBuffer buf = bufferMgr.createBuffer();
			initializeAllocatedBuffer(index, buf);
			addBuffer(index, buf);
			return buf;
		}
		return bufferMgr.getBuffer(bufferId);
	}

	/**
	 * Initialize specified DataBuffer which corresponds to the chain index.
	 * @param chainBufferIndex chain buffer index
	 * @param buf newly allocated database buffer
	 * @throws IOException thrown if an IO error occurs
	 */
	private void initializeAllocatedBuffer(int chainBufferIndex, DataBuffer buf)
			throws IOException {

		int offset = chainBufferIndex * dataSpace;
		int len = size - offset;
		if (len >= dataSpace) {
			len = dataSpace;
		}
		else {
			buf.clear(); // partial fill - clear entire buffer first
		}

		byte[] data = new byte[len];
		if (uninitializedDataSource != null) {
			uninitializedDataSource.get(uninitializedDataSourceOffset + offset, data, 0, len);
		}
		if (useXORMask) {
			for (int i = 0; i < len; i++) {
				data[i] = xorMaskByte(i, data[i]);
			}
		}
		buf.put(dataBaseOffset, data);
	}

	/**
	 * Add a new data buffer as an indexed buffer.
	 * @param index buffer index.
	 * @param buf new data buffer.
	 * @throws IOException thrown if an IO error occurs
	 */
	private void addBuffer(int index, DataBuffer buf) throws IOException {
		buf.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_DATA_NODE);
		dataBufferIdTable[index] = buf.getId();
		int indexBufferId = indexBufferIdTable[index / indexesPerBuffer];
		int indexOffset = INDEX_BASE_OFFSET + ((index % indexesPerBuffer) * ID_SIZE);
		DataBuffer indexBuffer = null;
		try {
			indexBuffer = bufferMgr.getBuffer(indexBufferId);
			indexBuffer.putInt(indexOffset, buf.getId());
			bufferMgr.releaseBuffer(indexBuffer);
		}
		finally {
			if (indexBuffer == null) {
				bufferMgr.releaseBuffer(buf);
			}
		}

	}

}
