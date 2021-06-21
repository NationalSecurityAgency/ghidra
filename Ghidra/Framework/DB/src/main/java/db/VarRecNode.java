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

import db.buffers.DataBuffer;
import ghidra.util.datastruct.IntArrayList;
import ghidra.util.exception.AssertException;

/**
 * <code>VarRecNode</code> is an implementation of a BTree leaf node
 * which utilizes long key values and stores variable-length records.
 * <p>
 * This type of node has the following layout within a single DataBuffer 
 * (field size in bytes):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | RecOffset0(4) | IndFlag0(1) |...  
 *     
 *   | KeyN(8) | RecOffsetN(4) | IndFlagN(1) |...<FreeSpace>... | RecN |... | Rec0 |
 * </pre>
 * IndFlag - if not zero the record has been stored within a chained DBBuffer 
 * whose 4-byte integer buffer ID has been stored within this leaf at the record offset.
 */
class VarRecNode extends LongKeyRecordNode {

	private static final int HEADER_SIZE = RECORD_LEAF_HEADER_SIZE;

	private static final int KEY_SIZE = 8;
	private static final int OFFSET_SIZE = 4;
	private static final int INDIRECT_OPTION_SIZE = 1;

	private static final int ENTRY_SIZE = KEY_SIZE + OFFSET_SIZE + INDIRECT_OPTION_SIZE;

	private static final int KEY_BASE_OFFSET = HEADER_SIZE;
	private static final int DATA_OFFSET_BASE_OFFSET = KEY_BASE_OFFSET + KEY_SIZE;
	private static final int IND_OPTION_BASE_OFFSET = DATA_OFFSET_BASE_OFFSET + OFFSET_SIZE;

	/**
	 * Construct an existing long-key variable-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 */
	VarRecNode(NodeMgr nodeMgr, DataBuffer buf) {
		super(nodeMgr, buf);
	}

	/**
	 * Construct a new long-key variable-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param prevLeafId node buffer id for previous leaf ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf ( &lt; 0 : no leaf)
	 * @throws IOException
	 */
	VarRecNode(NodeMgr nodeMgr, int prevLeafId, int nextLeafId) throws IOException {
		super(nodeMgr, NodeMgr.LONGKEY_VAR_REC_NODE, prevLeafId, nextLeafId);
	}

	@Override
	LongKeyRecordNode createNewLeaf(int prevLeafId, int nextLeafId) throws IOException {
		return new VarRecNode(nodeMgr, prevLeafId, nextLeafId);
	}

	@Override
	long getKey(int index) {
		return buffer.getLong(getKeyOffset(index));
	}

	@Override
	public int getKeyOffset(int index) {
		return KEY_BASE_OFFSET + (index * ENTRY_SIZE);
	}

	/**
	 * Get the record offset within the buffer
	 * @param index key index
	 * @return record offset
	 */
	int getRecordDataOffset(int index) {
		return buffer.getInt(DATA_OFFSET_BASE_OFFSET + (index * ENTRY_SIZE));
	}

	/**
	 * Store the record offset within the buffer for the specified key index
	 * @param index key index
	 * @param offset record offset
	 */
	private void putRecordDataOffset(int index, int offset) {
		buffer.putInt(DATA_OFFSET_BASE_OFFSET + (index * ENTRY_SIZE), offset);
	}

	/**
	 * Determine if a record is utilizing a chained DBBuffer for data storage
	 * @param index key index
	 * @return true if indirect storage is used for record, else false
	 */
	private boolean hasIndirectStorage(int index) {
		return buffer.getByte(IND_OPTION_BASE_OFFSET + (index * ENTRY_SIZE)) != 0;
	}

	/**
	 * Set the indirect storage flag associated with a record
	 * @param index key index
	 * @param state indirect storage used (true) or not used (false)
	 */
	private void enableIndirectStorage(int index, boolean state) {
		buffer.putByte(IND_OPTION_BASE_OFFSET + (index * ENTRY_SIZE), state ? (byte) 1 : (byte) 0);
	}

	/**
	 * @return unused free space within node
	 */
	private int getFreeSpace() {
		return (keyCount == 0 ? buffer.length() : getRecordDataOffset(keyCount - 1)) -
			(keyCount * ENTRY_SIZE) - RECORD_LEAF_HEADER_SIZE;
	}

	/**
	 * Get the length of a stored record.
	 * @param index index associated with record.
	 */
	private int getRecordLength(int index) {
		if (index == 0) {
			return buffer.length() - getRecordDataOffset(0);
		}
		return getRecordDataOffset(index - 1) - getRecordDataOffset(index);
	}

	/**
	 * Get the length of a stored record.  Optimized if record offset 
	 * already known.
	 * @param index index associated with record.
	 * @param offset record offset
	 */
	private int getRecordLength(int index, int offset) {
		if (index == 0) {
			return buffer.length() - offset;
		}
		return getRecordDataOffset(index - 1) - offset;
	}

	/**
	 * Move all record data, starting with index, by the specified offset amount.
	 * If the node contains 5 records, an index of 3 would shift the record data
	 * for indexes 3 and 4 left by the spacified offset amount.  This is used to 
	 * make space for a new or updated record.
	 * @param index the smaller key index (0 &lt;= index1)
	 * @param offset movement offset in bytes
	 * @return insertion offset immediately following moved block. 
	 */
	private int moveRecords(int index, int offset) {

		int lastIndex = keyCount - 1;

		// No movement needed for appended record
		if (index == keyCount) {
			if (index == 0) {
				return buffer.length() + offset;
			}
			return getRecordDataOffset(lastIndex) + offset;
		}

		// Determine block to be moved
		int start = getRecordDataOffset(lastIndex);
		int end = (index == 0) ? buffer.length() : getRecordDataOffset(index - 1);
		int len = end - start;

		// Move record data
		buffer.move(start, start + offset, len);

		// Adjust stored offsets
		for (int i = index; i < keyCount; i++) {
			putRecordDataOffset(i, getRecordDataOffset(i) + offset);
		}
		return end + offset;
	}

	@Override
	public DBRecord getRecord(Schema schema, int index) throws IOException {
		long key = getKey(index);
		DBRecord record = schema.createRecord(key);
		if (hasIndirectStorage(index)) {
			int bufId = buffer.getInt(getRecordDataOffset(index));
			ChainedBuffer chainedBuffer = new ChainedBuffer(nodeMgr.getBufferMgr(), bufId);
			record.read(chainedBuffer, 0);
		}
		else {
			record.read(buffer, getRecordDataOffset(index));
		}
		return record;
	}

	@Override
	public int getRecordOffset(int index) throws IOException {
		if (hasIndirectStorage(index)) {
			return -buffer.getInt(getRecordDataOffset(index));
		}
		return getRecordDataOffset(index);
	}

	@Override
	DBRecord getRecord(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			return null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Find the index which represents the halfway point within the record data.
	 * @return key index.
	 */
	private int getSplitIndex() {

		int halfway = ((keyCount == 0 ? buffer.length() : getRecordDataOffset(keyCount - 1)) +
			buffer.length()) / 2;
		int min = 1;
		int max = keyCount - 1;

		while (min < max) {
			int i = (min + max) / 2;
			int offset = getRecordDataOffset(i);
			if (offset == halfway) {
				return i;
			}
			else if (offset < halfway) {
				max = i - 1;
			}
			else {
				min = i + 1;
			}
		}
		return min;
	}

	@Override
	void splitData(LongKeyRecordNode newRightLeaf) {

		VarRecNode rightNode = (VarRecNode) newRightLeaf;

		int splitIndex = getSplitIndex();
		int count = keyCount - splitIndex;
		int start = getRecordDataOffset(keyCount - 1);	// start of block to be moved
		int end = getRecordDataOffset(splitIndex - 1);  // end of block to be moved
		int splitLen = end - start;				// length of block to be moved
		int rightOffset = buffer.length() - splitLen;    // data offset within new leaf node 

		// Copy data to new leaf node
		DataBuffer newBuf = rightNode.buffer;
		newBuf.copy(rightOffset, buffer, start, splitLen);
		newBuf.copy(KEY_BASE_OFFSET, buffer, KEY_BASE_OFFSET + (splitIndex * ENTRY_SIZE),
			count * ENTRY_SIZE);

		// Fix record offsets in new leaf node
		int offsetCorrection = buffer.length() - end;
		for (int i = 0; i < count; i++) {
			rightNode.putRecordDataOffset(i, rightNode.getRecordDataOffset(i) + offsetCorrection);
		}

		// Adjust key counts
		setKeyCount(keyCount - count);
		rightNode.setKeyCount(count);
	}

	@Override
	LongKeyNode updateRecord(int index, DBRecord record) throws IOException {

		int offset = getRecordDataOffset(index);
		int oldLen = getRecordLength(index, offset);
		int len = record.length();

		// Check for use of indirect chained record node(s)
		int maxRecordLength = ((buffer.length() - HEADER_SIZE) >> 2) - ENTRY_SIZE; // min 4 records per node
		boolean wasIndirect = hasIndirectStorage(index);
		boolean useIndirect = (len > maxRecordLength);

		if (useIndirect) {
			// Store record in chained buffers
			len = 4;
			ChainedBuffer chainedBuffer = null;
			if (wasIndirect) {
				chainedBuffer = new ChainedBuffer(nodeMgr.getBufferMgr(), buffer.getInt(offset));
				chainedBuffer.setSize(record.length(), false);
			}
			else {
				chainedBuffer = new ChainedBuffer(record.length(), nodeMgr.getBufferMgr());
				buffer.putInt(offset + oldLen - 4, chainedBuffer.getId()); // assumes old len is always > 4
				enableIndirectStorage(index, true);
			}
			record.write(chainedBuffer, 0);
		}
		else if (wasIndirect) {
			removeChainedBuffer(buffer.getInt(offset));
			enableIndirectStorage(index, false);
		}

		// See if updated record will fit in current buffer
		if (useIndirect || len <= (getFreeSpace() + oldLen)) {

			// Overwrite record data - move other data if needed			
			int dataShift = oldLen - len;
			if (dataShift != 0) {
				offset = moveRecords(index + 1, dataShift);
				putRecordDataOffset(index, offset);
			}
			if (!useIndirect) {
				record.write(buffer, offset);
			}
			return getRoot();
		}

		// Insufficient room for updated record	- remove and re-add
		long key = record.getKey();
		LongKeyRecordNode leaf = deleteRecord(key, null).getLeafNode(key);
		return leaf.putRecord(record, null);
	}

	@Override
	boolean insertRecord(int index, DBRecord record) throws IOException {

		// Check for use of indirect chained record node(s)
		int len = record.length();
		int maxRecordLength = ((buffer.length() - HEADER_SIZE) >> 2) - ENTRY_SIZE; // min 4 records per node
		boolean useIndirect = (len > maxRecordLength);
		if (useIndirect) {
			len = 4;
		}

		if ((len + ENTRY_SIZE) > getFreeSpace())
		 {
			return false;  // insufficient space for record storage
		}

		// Make room for new record
		int offset = moveRecords(index, -len);

		// Make room for new key/offset entry
		int start = KEY_BASE_OFFSET + (index * ENTRY_SIZE);
		len = (keyCount - index) * ENTRY_SIZE;
		buffer.move(start, start + ENTRY_SIZE, len);

		// Store new record key/offset
		buffer.putLong(start, record.getKey());
		buffer.putInt(start + KEY_SIZE, offset);
		setKeyCount(keyCount + 1);

		// Store record data
		if (useIndirect) {
			ChainedBuffer chainedBuffer =
				new ChainedBuffer(record.length(), nodeMgr.getBufferMgr());
			buffer.putInt(offset, chainedBuffer.getId());
			record.write(chainedBuffer, 0);
		}
		else {
			record.write(buffer, offset);
		}
		enableIndirectStorage(index, useIndirect);

		return true;
	}

	@Override
	public void remove(int index) throws IOException {

		if (index < 0 || index >= keyCount) {
			throw new AssertException();
		}

		if (hasIndirectStorage(index)) {
			removeChainedBuffer(buffer.getInt(getRecordDataOffset(index)));
			enableIndirectStorage(index, false);
		}

		int len = getRecordLength(index);

		moveRecords(index + 1, len);

		int start = KEY_BASE_OFFSET + ((index + 1) * ENTRY_SIZE);
		len = (keyCount - index - 1) * ENTRY_SIZE;
		buffer.move(start, start - ENTRY_SIZE, len);
		setKeyCount(keyCount - 1);
	}

	/**
	 * Removes this leaf and all associated chained buffers.
	 * @see db.LongKeyRecordNode#removeLeaf()
	 */
	@Override
	public LongKeyNode removeLeaf() throws IOException {

		// Remove all chained buffers associated with this leaf
		for (int index = 0; index < keyCount; ++index) {
			if (hasIndirectStorage(index)) {
				removeChainedBuffer(buffer.getInt(getRecordDataOffset(index)));
			}
		}
		return super.removeLeaf();
	}

	/**
	 * Remove a chained buffer.
	 * @param bufferId chained buffer ID
	 */
	private void removeChainedBuffer(int bufferId) throws IOException {
		ChainedBuffer chainedBuffer = new ChainedBuffer(nodeMgr.getBufferMgr(), bufferId);
		chainedBuffer.delete();
	}

	@Override
	public void delete() throws IOException {

		// Remove all chained buffers associated with this node.
		for (int index = 0; index < keyCount; index++) {
			if (hasIndirectStorage(index)) {
				int offset = getRecordDataOffset(index);
				int bufferId = buffer.getInt(offset);
				removeChainedBuffer(bufferId);
				buffer.putInt(offset, -1);
			}
		}

		// Remove this node
		nodeMgr.deleteNode(this);
	}

	@Override
	public int[] getBufferReferences() {
		IntArrayList idList = new IntArrayList();
		for (int i = 0; i < keyCount; i++) {
			if (hasIndirectStorage(i)) {
				int offset = getRecordDataOffset(i);
				idList.add(buffer.getInt(offset));
			}
		}
		return idList.toArray();
	}

}
