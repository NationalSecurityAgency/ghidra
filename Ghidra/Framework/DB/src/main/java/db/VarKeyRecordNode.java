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
import ghidra.util.Msg;
import ghidra.util.datastruct.IntArrayList;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>VarKeyRecordNode</code> is an implementation of a BTree leaf node
 * which utilizes variable-length key values and stores variable-length records.
 * This type of node has the following layout within a single DataBuffer 
 * (field size in bytes):
 * <pre>
 *   |   NodeType(1) | KeyType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | KeyOffset0(4) | IndFlag0(1) |...      
 * 
 *   | KeyOffsetN(4) | IndFlagN(1) |...&lt;FreeSpace&gt;... | KeyN | RecN |... | Key0 | Rec0 |
 * </pre>
 * IndFlag - if not zero the record has been stored within a chained DBBuffer 
 * whose 4-byte integer buffer ID has been stored within this leaf at the record offset.
 */
class VarKeyRecordNode extends VarKeyNode implements FieldKeyRecordNode {

	private static final int ID_SIZE = 4;

	private static final int PREV_LEAF_ID_OFFSET = VARKEY_NODE_HEADER_SIZE;
	private static final int NEXT_LEAF_ID_OFFSET = PREV_LEAF_ID_OFFSET + ID_SIZE;

	static final int HEADER_SIZE = VARKEY_NODE_HEADER_SIZE + 2 * ID_SIZE;

	private static final int OFFSET_SIZE = 4;
	private static final int INDIRECT_OPTION_SIZE = 1;

	private static final int ENTRY_SIZE = OFFSET_SIZE + INDIRECT_OPTION_SIZE;

	/**
	 * Construct an existing variable-length-key record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyRecordNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		super(nodeMgr, buf);
	}

	/**
	 * Construct a new variable-length-key record leaf node.
	 * @param nodeMgr table node manager.
	 * @param prevLeafId node buffer id for previous leaf ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf ( &lt; 0 : no leaf)
	 * @param keyType key Field type
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyRecordNode(NodeMgr nodeMgr, int prevLeafId, int nextLeafId, Field keyType)
			throws IOException {
		super(nodeMgr, NodeMgr.VARKEY_REC_NODE, keyType);

		// Initialize header
		buffer.putInt(PREV_LEAF_ID_OFFSET, prevLeafId);
		buffer.putInt(NEXT_LEAF_ID_OFFSET, nextLeafId);
	}

	/**
	 * Construct a new variable-length-key record leaf node with no siblings.
	 * @param nodeMgr table node manager.
	 * @param keyType key Field type
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyRecordNode(NodeMgr nodeMgr, Field keyType) throws IOException {
		super(nodeMgr, NodeMgr.VARKEY_REC_NODE, keyType);

		// Initialize header
		buffer.putInt(PREV_LEAF_ID_OFFSET, -1);
		buffer.putInt(NEXT_LEAF_ID_OFFSET, -1);
	}

	void logConsistencyError(String tableName, String msg, Throwable t) throws IOException {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this, "  bufferID=" + getBufferId() + " key[0]=" + getKeyField(0));
		if (t != null) {
			Msg.error(this, "Consistency Error (" + tableName + ")", t);
		}
	}

	@Override
	public boolean isConsistent(String tableName, TaskMonitor monitor)
			throws IOException, CancelledException {
		boolean consistent = true;
		Field prevKey = null;
		for (int i = 0; i < keyCount; i++) {
			// Compare each key entry with the previous key
			Field key = getKeyField(i);
			if (i != 0) {
				if (key.compareTo(prevKey) <= 0) {
					consistent = false;
					logConsistencyError(tableName, "key[" + i + "] <= key[" + (i - 1) + "]", null);
					Msg.debug(this, "  key[" + i + "].minKey = " + key);
					Msg.debug(this, "  key[" + (i - 1) + "].minKey = " + prevKey);
				}
			}
			prevKey = key;
		}

		if ((parent == null || parent.isLeftmostKey(getKeyField(0))) && getPreviousLeaf() != null) {
			consistent = false;
			logConsistencyError(tableName, "previous-leaf should not exist", null);
		}

		VarKeyRecordNode node = getNextLeaf();
		if (node != null) {
			if (parent == null || parent.isRightmostKey(getKeyField(0))) {
				consistent = false;
				logConsistencyError(tableName, "next-leaf should not exist", null);
			}
			else {
				VarKeyRecordNode me = node.getPreviousLeaf();
				if (me != this) {
					consistent = false;
					logConsistencyError(tableName, "next-leaf is not linked to this leaf", null);
				}
			}
		}
		else if (parent != null && !parent.isRightmostKey(getKeyField(0))) {
			consistent = false;
			logConsistencyError(tableName, "this leaf is not linked to next-leaf", null);
		}

		return consistent;
	}

	@Override
	public VarKeyRecordNode getLeafNode(Field key) throws IOException {
		return this;
	}

	@Override
	public VarKeyRecordNode getLeftmostLeafNode() throws IOException {
		VarKeyRecordNode leaf = getPreviousLeaf();
		return leaf != null ? leaf.getLeftmostLeafNode() : this;
	}

	@Override
	public VarKeyRecordNode getRightmostLeafNode() throws IOException {
		VarKeyRecordNode leaf = getNextLeaf();
		return leaf != null ? leaf.getRightmostLeafNode() : this;
	}

	@Override
	public boolean hasNextLeaf() throws IOException {
		int nextLeafId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		return (nextLeafId >= 0);
	}

	/**
	 * Get this leaf node's right sibling
	 * @return this leaf node's right sibling or null if right sibling does not exist.
	 * @throws IOException thrown if an IO error occurs
	 */
	@Override
	public VarKeyRecordNode getNextLeaf() throws IOException {
		VarKeyRecordNode leaf = null;
		int nextLeafId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (nextLeafId >= 0) {
			leaf = (VarKeyRecordNode) nodeMgr.getVarKeyNode(nextLeafId);
		}
		return leaf;
	}

	@Override
	public boolean hasPreviousLeaf() throws IOException {
		int prevLeafId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		return (prevLeafId >= 0);
	}

	/**
	 * Get this leaf node's left sibling
	 * @return this leaf node's left sibling or null if left sibling does not exist.
	 * @throws IOException if an IO error occurs
	 */
	@Override
	public VarKeyRecordNode getPreviousLeaf() throws IOException {
		VarKeyRecordNode leaf = null;
		int prevLeafId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		if (prevLeafId >= 0) {
			leaf = (VarKeyRecordNode) nodeMgr.getVarKeyNode(prevLeafId);
		}
		return leaf;
	}

	@Override
	public int getKeyIndex(Field key) throws IOException {

		int min = 0;
		int max = keyCount - 1;

		while (min <= max) {
			int i = (min + max) / 2;
			int rc = compareKeyField(key, i);
			if (rc == 0) {
				return i;
			}
			else if (rc > 0) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return -(min + 1);
	}

	/**
	 * Split this leaf node in half and update tree.
	 * When a split is performed, the next operation must be performed
	 * from the root node since the tree may have been restructured.
	 * @return root node which may have changed.
	 * @throws IOException thrown if an IO error occurs
	 */
	VarKeyNode split() throws IOException {

		// Create new leaf
		int oldSiblingId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		VarKeyRecordNode newLeaf = createNewLeaf(buffer.getId(), oldSiblingId);
		DataBuffer newBuf = newLeaf.buffer;
		int newBufId = newBuf.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		if (oldSiblingId >= 0) {
			VarKeyRecordNode leaf = (VarKeyRecordNode) nodeMgr.getVarKeyNode(oldSiblingId);
			leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		// Split node creating two balanced leaves
		splitData(newLeaf);

		if (parent != null) {
			// Ask parent to insert new node and return root
			return parent.insert(newLeaf);
		}

		// New parent node becomes root
		return new VarKeyInteriorNode(nodeMgr, getKeyField(0), buffer.getId(),
			newLeaf.getKeyField(0), newBufId);
	}

	/**
	 * Append a leaf which contains one or more keys and update tree.  Leaf is inserted
	 * as the new right sibling of this leaf.
	 * @param leaf new right sibling leaf (must be same node type as this leaf)
	 * @return root node which may have changed.
	 * @throws IOException thrown if an IO error occurs
	 */
	VarKeyNode appendLeaf(VarKeyRecordNode leaf) throws IOException {

		// Create new leaf and link
		leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, buffer.getId());
		int rightLeafBufId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		leaf.buffer.putInt(NEXT_LEAF_ID_OFFSET, rightLeafBufId);

		// Adjust this node
		int newBufId = leaf.buffer.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		// Adjust old right node if present
		if (rightLeafBufId >= 0) {
			VarKeyNode rightLeaf = nodeMgr.getVarKeyNode(rightLeafBufId);
			rightLeaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		if (parent != null) {
			// Ask parent to insert new node and return root - leaf parent is unknown
			return parent.insert(leaf);
		}

		// New parent node becomes root
		return new VarKeyInteriorNode(nodeMgr, getKeyField(0), buffer.getId(), leaf.getKeyField(0),
			newBufId);
	}

	@Override
	public VarKeyNode putRecord(DBRecord record, Table table) throws IOException {

		Field key = record.getKeyField();
		int index = getKeyIndex(key);

		// Handle record update case
		if (index >= 0) {
			if (table != null) {
				table.updatedRecord(getRecord(table.getSchema(), index), record);
			}
			VarKeyNode newRoot = updateRecord(index, record);
			return newRoot;
		}

		// Handle new record - see if we have room in this leaf
		index = -index - 1;
		if (insertRecord(index, record)) {
			if (index == 0 && parent != null) {
				parent.keyChanged(getKeyField(1), key, this);
			}
			if (table != null) {
				table.insertedRecord(record);
			}
			return getRoot();
		}

		// Special Case - append new leaf to right
		if (index == keyCount) {
			VarKeyNode newRoot = appendNewLeaf(record);
			if (table != null) {
				table.insertedRecord(record);
			}
			return newRoot;
		}

		// Split leaf and complete insertion
		VarKeyRecordNode leaf = split().getLeafNode(key);
		return leaf.putRecord(record, table);
	}

	/**
	 * Append a new leaf and insert the specified record.
	 * @param record data record with long key
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyNode appendNewLeaf(DBRecord record) throws IOException {
		VarKeyRecordNode newLeaf = createNewLeaf(-1, -1);
		newLeaf.insertRecord(0, record);
		return appendLeaf(newLeaf);
	}

	/**
	 * Delete the record identified by the specified key.
	 * @param key record key
	 * @param table table which will be notified when record is deleted.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public VarKeyNode deleteRecord(Field key, Table table) throws IOException {

		// Handle non-existent key - do nothing
		int index = getKeyIndex(key);
		if (index < 0) {
			return getRoot();
		}

		if (table != null) {
			table.deletedRecord(getRecord(table.getSchema(), index));
		}

		// Handle removal of last record in node
		if (keyCount == 1) {
			VarKeyNode newRoot = removeLeaf();
			return newRoot;
		}

		// Remove record within this node
		remove(index);

		// Notify parent of leftmost key change
		if (index == 0 && parent != null) {
			parent.keyChanged(key, getKeyField(0), this);
		}

		return getRoot();
	}

	@Override
	public DBRecord getRecordBefore(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -index - 2;
		}
		else {
			--index;
		}
		if (index < 0) {
			VarKeyRecordNode nextLeaf = getPreviousLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, nextLeaf.keyCount - 1) : null;
		}
		return getRecord(schema, index);
	}

	@Override
	public DBRecord getRecordAfter(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -(index + 1);
		}
		else {
			++index;
		}
		if (index == keyCount) {
			VarKeyRecordNode nextLeaf = getNextLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, 0) : null;
		}
		return getRecord(schema, index);
	}

	@Override
	public DBRecord getRecordAtOrBefore(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -index - 2;
		}
		if (index < 0) {
			VarKeyRecordNode nextLeaf = getPreviousLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, nextLeaf.keyCount - 1) : null;
		}
		return getRecord(schema, index);
	}

	@Override
	public DBRecord getRecordAtOrAfter(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -(index + 1);
		}
		if (index == keyCount) {
			VarKeyRecordNode nextLeaf = getNextLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, 0) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Create a new leaf and add to the node manager.
	 * The new leaf's parent is unknown.
	 * @param prevLeafId node buffer id for previous leaf - left sibling ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf - right sibling ( &lt; 0 : no leaf)
	 * @return new leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyRecordNode createNewLeaf(int prevLeafId, int nextLeafId) throws IOException {
		return new VarKeyRecordNode(nodeMgr, prevLeafId, nextLeafId, keyType);
	}

	@Override
	public Field getKeyField(int index) throws IOException {
		Field key = keyType.newField();
		key.read(buffer, getKeyOffset(index));
		return key;
	}

	@Override
	public int getKeyOffset(int index) {
		return buffer.getInt(HEADER_SIZE + (index * ENTRY_SIZE));
	}

	/**
	 * Get the record data offset within the buffer
	 * @param index key index
	 * @return record data offset
	 */
	private int getRecordDataOffset(int index) throws IOException {
		int offset = getKeyOffset(index);
		return offset + keyType.readLength(buffer, offset);
	}

	/**
	 * Get the record key offset within the buffer
	 * @param index key index
	 * @return record key offset
	 */
	private int getRecordKeyOffset(int index) {
		return buffer.getInt(HEADER_SIZE + (index * ENTRY_SIZE));
	}

	/**
	 * Store the record key offset within the buffer for the specified key index.
	 * The record data immediately follows the stored key for the record.
	 * @param index key index
	 * @param offset key offset
	 */
	private void putRecordKeyOffset(int index, int offset) {
		buffer.putInt(HEADER_SIZE + (index * ENTRY_SIZE), offset);
	}

	/**
	 * Determine if a record is utilizing a chained DBBuffer for data storage
	 * @param index key index
	 * @return true if indirect storage is used for record, else false
	 */
	private boolean hasIndirectStorage(int index) {
		return buffer.getByte(HEADER_SIZE + OFFSET_SIZE + (index * ENTRY_SIZE)) != 0;
	}

	/**
	 * Set the indirect storage flag associated with a record
	 * @param index key index
	 * @param state indirect storage used (true) or not used (false)
	 */
	private void enableIndirectStorage(int index, boolean state) {
		buffer.putByte(HEADER_SIZE + OFFSET_SIZE + (index * ENTRY_SIZE),
			state ? (byte) 1 : (byte) 0);
	}

	/**
	 * @return unused free space within node
	 */
	private int getFreeSpace() {
		return (keyCount == 0 ? buffer.length() : getRecordKeyOffset(keyCount - 1)) -
			(keyCount * ENTRY_SIZE) - HEADER_SIZE;
	}

	/**
	 * Get the length of a stored record with key.
	 * @param index key index associated with record.
	 */
	private int getFullRecordLength(int index) {
		if (index == 0) {
			return buffer.length() - getRecordKeyOffset(0);
		}
		return getRecordKeyOffset(index - 1) - getRecordKeyOffset(index);
	}

	/**
	 * Move all records from index to the end by the specified offset.
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
			return getRecordKeyOffset(lastIndex) + offset;
		}

		// Determine block to be moved
		int start = getRecordKeyOffset(lastIndex);
		int end = (index == 0) ? buffer.length() : getRecordKeyOffset(index - 1);
		int len = end - start;

		// Move record data
		buffer.move(start, start + offset, len);

		// Adjust stored offsets
		for (int i = index; i < keyCount; i++) {
			putRecordKeyOffset(i, getRecordKeyOffset(i) + offset);
		}
		return end + offset;
	}

	/**
	 * Get the record located at the specified index.
	 * @param schema record data schema
	 * @param index key index
	 * @return Record
	 */
	@Override
	public DBRecord getRecord(Schema schema, int index) throws IOException {
		Field key = getKeyField(index);
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
	public DBRecord getRecord(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0)
			return null;
		return getRecord(schema, index);
	}

	/**
	 * Find the index which represents the halfway point within the record data.
	 * @return key index.
	 */
	private int getSplitIndex() {

		int halfway = ((keyCount == 0 ? buffer.length() : getRecordKeyOffset(keyCount - 1)) +
			buffer.length()) / 2;
		int min = 0;
		int max = keyCount - 1;

		while (min <= max) {
			int i = (min + max) / 2;
			int offset = getRecordKeyOffset(i);
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

	/**
	 * Split the contents of this leaf node; placing the right half of the records into the
	 * empty leaf node provided.
	 * @param rightNode empty right sibling leaf
	 */
	private void splitData(VarKeyRecordNode rightNode) {

		int splitIndex = getSplitIndex();
		int count = keyCount - splitIndex;
		int start = getRecordKeyOffset(keyCount - 1);	// start of block to be moved
		int end = getRecordKeyOffset(splitIndex - 1);  // end of block to be moved
		int splitLen = end - start;				// length of block to be moved
		int rightOffset = buffer.length() - splitLen;    // data offset within new leaf node 

		// Copy data to new leaf node
		DataBuffer newBuf = rightNode.buffer;
		newBuf.copy(rightOffset, buffer, start, splitLen);
		newBuf.copy(HEADER_SIZE, buffer, HEADER_SIZE + (splitIndex * ENTRY_SIZE),
			count * ENTRY_SIZE);

		// Fix record offsets in new leaf node
		int offsetCorrection = buffer.length() - end;
		for (int i = 0; i < count; i++) {
			rightNode.putRecordKeyOffset(i, rightNode.getRecordKeyOffset(i) + offsetCorrection);
		}

		// Adjust key counts
		setKeyCount(keyCount - count);
		rightNode.setKeyCount(count);
	}

	/**
	 * Updates the record at the given index. 
	 * @param index record index
	 * @param record new record
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	private VarKeyNode updateRecord(int index, DBRecord record) throws IOException {

		Field key = record.getKeyField();
		int keyLen = key.length();

		int offset = getRecordKeyOffset(index);
		int oldLen = getFullRecordLength(index) - keyLen;
		int len = record.length();

		// Check for use of indirect chained record node(s)
		int maxRecordLength = ((buffer.length() - HEADER_SIZE) >> 2) - ENTRY_SIZE - keyLen; // min 4 records per node
		boolean wasIndirect = hasIndirectStorage(index);
		boolean useIndirect = (len > maxRecordLength);

		if (useIndirect) {
			// Store record in chained buffers
			len = 4;
			ChainedBuffer chainedBuffer = null;
			if (wasIndirect) {
				chainedBuffer =
					new ChainedBuffer(nodeMgr.getBufferMgr(), buffer.getInt(offset + keyLen));
				chainedBuffer.setSize(record.length(), false);
			}
			else {
				chainedBuffer = new ChainedBuffer(record.length(), nodeMgr.getBufferMgr());
				buffer.putInt(offset + keyLen + oldLen - 4, chainedBuffer.getId()); // assumes old len is always > 4
				enableIndirectStorage(index, true);
			}
			record.write(chainedBuffer, 0);
		}
		else if (wasIndirect) {
			removeChainedBuffer(buffer.getInt(offset + keyLen));
			enableIndirectStorage(index, false);
		}

		// See if updated record will fit in current buffer
		if (useIndirect || len <= (getFreeSpace() + oldLen)) {

			// Overwrite record data - move other data if needed			
			int dataShift = oldLen - len;
			if (dataShift != 0) {
				offset = moveRecords(index + 1, dataShift);
				putRecordKeyOffset(index, offset);
				key.write(buffer, offset);
			}
			if (!useIndirect) {
				record.write(buffer, offset + keyLen);
			}
			return getRoot();
		}

		// Insufficient room for updated record	- remove and re-add
		VarKeyRecordNode leaf = deleteRecord(key, null).getLeafNode(key);
		return leaf.putRecord(record, null);
	}

	/**
	 * Inserts the record at the given index if there is sufficient space in
	 * the buffer. 
	 * @param index insertion index
	 * @param record record to be inserted
	 * @return true if the record was successfully inserted.
	 * @throws IOException thrown if IO error occurs
	 */
	private boolean insertRecord(int index, DBRecord record) throws IOException {

		Field key = record.getKeyField();
		int keyLen = key.length();
		if (keyLen > maxKeyLength)
			throw new AssertException("Key exceeds maximum key length of " + maxKeyLength);

		// Check for use of indirect chained record node(s)
		int len = record.length();
		int maxRecordLength = ((buffer.length() - HEADER_SIZE) >> 2) - ENTRY_SIZE - keyLen; // min 4 records per node
		boolean useIndirect = (len > maxRecordLength);
		if (useIndirect) {
			len = 4;
		}

		if ((len + keyLen + ENTRY_SIZE) > getFreeSpace())
			return false;  // insufficient space for record storage

		// Make room for new record
		int offset = moveRecords(index, -(len + keyLen));

		// Make room for new key/offset entry
		int start = HEADER_SIZE + (index * ENTRY_SIZE);
		len = (keyCount - index) * ENTRY_SIZE;
		buffer.move(start, start + ENTRY_SIZE, len);

		// Store new record key/offset
		buffer.putInt(start, offset);
		setKeyCount(keyCount + 1);
		key.write(buffer, offset);

		// Store record data
		if (useIndirect) {
			ChainedBuffer chainedBuffer =
				new ChainedBuffer(record.length(), nodeMgr.getBufferMgr());
			buffer.putInt(offset + keyLen, chainedBuffer.getId());
			record.write(chainedBuffer, 0);
		}
		else {
			record.write(buffer, offset + keyLen);
		}
		enableIndirectStorage(index, useIndirect);

		return true;
	}

	/**
	 * Remove the record identified by index.
	 * This will never be the last record within the node.
	 * @param index record index
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public void remove(int index) throws IOException {

		if (index < 0 || index >= keyCount)
			throw new AssertException();

		if (hasIndirectStorage(index)) {
			removeChainedBuffer(buffer.getInt(getRecordDataOffset(index)));
			enableIndirectStorage(index, false);
		}

		int len = getFullRecordLength(index);
		moveRecords(index + 1, len);

		int start = HEADER_SIZE + ((index + 1) * ENTRY_SIZE);
		len = (keyCount - index - 1) * ENTRY_SIZE;
		buffer.move(start, start - ENTRY_SIZE, len);
		setKeyCount(keyCount - 1);
	}

	/**
	 * Remove this leaf and all associated chained buffers from the tree.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public VarKeyNode removeLeaf() throws IOException {

		// Remove all chained buffers associated with this leaf
		for (int index = 0; index < keyCount; ++index) {
			if (hasIndirectStorage(index)) {
				removeChainedBuffer(buffer.getInt(getRecordDataOffset(index)));
			}
		}

		Field key = getKeyField(0);
		int prevBufferId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		int nextBufferId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (prevBufferId >= 0) {
			VarKeyRecordNode prevNode = (VarKeyRecordNode) nodeMgr.getVarKeyNode(prevBufferId);
			prevNode.getBuffer().putInt(NEXT_LEAF_ID_OFFSET, nextBufferId);
		}
		if (nextBufferId >= 0) {
			VarKeyRecordNode nextNode = (VarKeyRecordNode) nodeMgr.getVarKeyNode(nextBufferId);
			nextNode.getBuffer().putInt(PREV_LEAF_ID_OFFSET, prevBufferId);
		}

		nodeMgr.deleteNode(this);
		if (parent == null) {
			return null;
		}
		return parent.deleteChild(key);
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
				try {
					int offset = getRecordDataOffset(i);
					idList.add(buffer.getInt(offset));
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
		return idList.toArray();
	}

}
