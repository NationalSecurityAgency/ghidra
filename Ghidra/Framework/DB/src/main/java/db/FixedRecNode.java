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
import ghidra.util.exception.AssertException;

/**
 * <code>FixedRecNode</code> is an implementation of a BTree leaf node
 * which utilizes long key values and stores fixed-length records.
 * <p>
 * This type of node has the following layout within a single DataBuffer 
 * (field size in bytes):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | Rec0 | ...
 * 
 *   | KeyN(8) | RecN |
 * </pre>
 */
class FixedRecNode extends LongKeyRecordNode {

	private static final int HEADER_SIZE = RECORD_LEAF_HEADER_SIZE;

	private static final int ENTRY_BASE_OFFSET = HEADER_SIZE;

	private static final int KEY_SIZE = 8;

	private static final int[] EMPTY_ID_LIST = new int[0];

	private int entrySize;
	private int recordLength;

	/**
	 * Construct an existing long-key fixed-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @param recordLength fixed record length
	 */
	FixedRecNode(NodeMgr nodeMgr, DataBuffer buf, int recordLength) {
		super(nodeMgr, buf);
		this.recordLength = recordLength;
		entrySize = KEY_SIZE + recordLength;
	}

	/**
	 * Construct a new long-key fixed-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param recordLength fixed record length
	 * @param prevLeafId node buffer id for previous leaf ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf ( &lt; 0 : no leaf)
	 * @throws IOException thrown if IO error occurs
	 */
	FixedRecNode(NodeMgr nodeMgr, int recordLength, int prevLeafId, int nextLeafId)
			throws IOException {
		super(nodeMgr, NodeMgr.LONGKEY_FIXED_REC_NODE, prevLeafId, nextLeafId);
		this.recordLength = recordLength;
		entrySize = KEY_SIZE + recordLength;
	}

	@Override
	LongKeyRecordNode createNewLeaf(int prevLeafId, int nextLeafId) throws IOException {
		return new FixedRecNode(nodeMgr, recordLength, prevLeafId, nextLeafId);
	}

	@Override
	long getKey(int index) {
		return buffer.getLong(getKeyOffset(index));
	}

	@Override
	public int getKeyOffset(int index) {
		return ENTRY_BASE_OFFSET + (index * entrySize);
	}

	/**
	 * Get the record offset within the buffer
	 * @param index key index
	 * @return record offset
	 */
	@Override
	public int getRecordOffset(int index) {
		return ENTRY_BASE_OFFSET + (index * entrySize);
	}

	/**
	 * Shift all records by one starting with index to the end.
	 * @param index the smaller key index (0 &lt;= index1)
	 * @param rightShift shift right by one record if true, else shift left by
	 * one record.
	 */
	private void shiftRecords(int index, boolean rightShift) {

		// No movement needed for appended record
		if (index == keyCount)
			return;

		// Determine block to be moved
		int start = getRecordOffset(index);
		int end = getRecordOffset(keyCount);
		int len = end - start;

		// Move record data
		int offset = start + (rightShift ? entrySize : -entrySize);
		buffer.move(start, offset, len);
	}

	@Override
	public void remove(int index) {

		if (index < 0 || index >= keyCount)
			throw new AssertException();

		shiftRecords(index + 1, false);
		setKeyCount(keyCount - 1);
	}

	@Override
	boolean insertRecord(int index, DBRecord record) throws IOException {

		if (keyCount == ((buffer.length() - HEADER_SIZE) / entrySize)) {
			return false;  // insufficient space for record storage
		}

		// Make room for new record
		shiftRecords(index, true);

		// Store new record
		int offset = getRecordOffset(index);
		buffer.putLong(offset, record.getKey());
		record.write(buffer, offset + KEY_SIZE);
		setKeyCount(keyCount + 1);

		return true;
	}

	@Override
	LongKeyNode updateRecord(int index, DBRecord record) throws IOException {
		int offset = getRecordOffset(index) + KEY_SIZE;
		record.write(buffer, offset);
		return getRoot();
	}

	@Override
	DBRecord getRecord(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0)
			return null;
		DBRecord record = schema.createRecord(key);
		record.read(buffer, getRecordOffset(index) + KEY_SIZE);
		return record;
	}

	@Override
	public DBRecord getRecord(Schema schema, int index) throws IOException {
		long key = getKey(index);
		DBRecord record = schema.createRecord(key);
		record.read(buffer, getRecordOffset(index) + KEY_SIZE);
		return record;
	}

	@Override
	void splitData(LongKeyRecordNode newRightLeaf) {

		FixedRecNode rightNode = (FixedRecNode) newRightLeaf;

		int splitIndex = keyCount / 2;
		int count = keyCount - splitIndex;
		int start = getRecordOffset(splitIndex);		// start of block to be moved
		int end = getRecordOffset(keyCount);	  		// end of block to be moved
		int splitLen = end - start;					// length of block to be moved

		// Copy data to new leaf node
		rightNode.buffer.copy(ENTRY_BASE_OFFSET, buffer, start, splitLen);

		// Adjust key counts
		setKeyCount(keyCount - count);
		rightNode.setKeyCount(count);
	}

	@Override
	public void delete() throws IOException {
		nodeMgr.deleteNode(this);
	}

	@Override
	public int[] getBufferReferences() {
		return EMPTY_ID_LIST;
	}

}
