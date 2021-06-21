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
 * <code>FixedKeyFixedRecNode</code> is an implementation of a BTree leaf node
 * which utilizes fixed-length key values and stores fixed-length records.
 * <p>
 * This type of node has the following layout within a single DataBuffer 
 * (field size in bytes, where 'L' is the fixed length of the fixed-length 
 * key as specified by key type in associated Schema):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(L) | Rec0 | ...
 * 
 *   | KeyN(L) | RecN |
 * </pre>
 */
class FixedKeyFixedRecNode extends FixedKeyRecordNode {

	private static final int HEADER_SIZE = RECORD_LEAF_HEADER_SIZE;

	private static final int ENTRY_BASE_OFFSET = HEADER_SIZE;

	private static final int[] EMPTY_ID_LIST = new int[0];

	private int entrySize;
	private int recordLength;

	/**
	 * Construct an existing fixed-length key fixed-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException if IO error occurs
	 */
	FixedKeyFixedRecNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		super(nodeMgr, buf);
		this.recordLength = nodeMgr.getTableSchema().getFixedLength();
		entrySize = keySize + recordLength;
	}

	/**
	 * Construct a new fixed-length key fixed-length record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param prevLeafId node buffer id for previous leaf ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf ( &lt; 0 : no leaf)
	 * @throws IOException if IO error occurs
	 */
	FixedKeyFixedRecNode(NodeMgr nodeMgr, int prevLeafId, int nextLeafId) throws IOException {
		super(nodeMgr, NodeMgr.FIXEDKEY_FIXED_REC_NODE, prevLeafId, nextLeafId);
		this.recordLength = nodeMgr.getTableSchema().getFixedLength();
		entrySize = keySize + recordLength;
	}

	@Override
	FixedKeyRecordNode createNewLeaf(int prevLeafId, int nextLeafId) throws IOException {
		return new FixedKeyFixedRecNode(nodeMgr, prevLeafId, nextLeafId);
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

		// Check for use of indirect chained record node(s)
//		int len = record.length();

		if (keyCount == ((buffer.length() - HEADER_SIZE) / entrySize))
			return false;  // insufficient space for record storage

		// Make room for new record
		shiftRecords(index, true);

		// Store new record
		int offset = getRecordOffset(index);
		record.getKeyField().write(buffer, offset);
		record.write(buffer, offset + keySize);
		setKeyCount(keyCount + 1);

		return true;
	}

	@Override
	FixedKeyNode updateRecord(int index, DBRecord record) throws IOException {
		int offset = getRecordOffset(index) + keySize;
		record.write(buffer, offset);
		return getRoot();
	}

	@Override
	public DBRecord getRecord(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0)
			return null;
		DBRecord record = schema.createRecord(key);
		record.read(buffer, getRecordOffset(index) + keySize);
		return record;
	}

	@Override
	public DBRecord getRecord(Schema schema, int index) throws IOException {
		Field key = getKeyField(index);
		DBRecord record = schema.createRecord(key);
		record.read(buffer, getRecordOffset(index) + keySize);
		return record;
	}

	@Override
	void splitData(FixedKeyRecordNode newRightLeaf) {

		FixedKeyFixedRecNode rightNode = (FixedKeyFixedRecNode) newRightLeaf;

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
