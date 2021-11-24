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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LongKeyRecordNode</code> is an abstract implementation of a BTree leaf node
 * which utilizes long key values and stores records.
 * <p>
 * This type of node has the following partial layout within a single DataBuffer
 * (field size in bytes):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | ...
 * </pre>
 */
abstract class LongKeyRecordNode extends LongKeyNode implements RecordNode {

	private static final int ID_SIZE = 4;

	private static final int PREV_LEAF_ID_OFFSET = LONGKEY_NODE_HEADER_SIZE;
	private static final int NEXT_LEAF_ID_OFFSET = PREV_LEAF_ID_OFFSET + ID_SIZE;

	static final int RECORD_LEAF_HEADER_SIZE = LONGKEY_NODE_HEADER_SIZE + 2 * ID_SIZE;

	/**
	 * Construct an existing long-key record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 */
	LongKeyRecordNode(NodeMgr nodeMgr, DataBuffer buf) {
		super(nodeMgr, buf);
	}

	/**
	 * Construct a new long-key record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param nodeType node type
	 * @param prevLeafId node buffer id for previous leaf - left sibling ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf - right sibling ( &lt; 0 : no leaf)
	 * @throws IOException thrown if an IO error occurs
	 */
	LongKeyRecordNode(NodeMgr nodeMgr, byte nodeType, int prevLeafId, int nextLeafId)
			throws IOException {
		super(nodeMgr, nodeType);

		// Initialize header
		buffer.putInt(PREV_LEAF_ID_OFFSET, prevLeafId);
		buffer.putInt(NEXT_LEAF_ID_OFFSET, nextLeafId);
	}

	@Override
	public LongKeyInteriorNode getParent() {
		return parent;
	}

	void logConsistencyError(String tableName, String msg, Throwable t) {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this, "  bufferID=" + getBufferId() + " key[0]=0x" + Long.toHexString(getKey(0)));
		if (t != null) {
			Msg.error(this, "Consistency Error (" + tableName + ")", t);
		}
	}

	@Override
	public boolean isConsistent(String tableName, TaskMonitor monitor)
			throws IOException, CancelledException {
		boolean consistent = true;
		long prevKey = 0;
		for (int i = 0; i < keyCount; i++) {
			// Compare each key entry with the previous key
			long key = getKey(i);
			if (i != 0) {
				if (key <= prevKey) {
					consistent = false;
					logConsistencyError(tableName, "key[" + i + "] <= key[" + (i - 1) + "]", null);
					Msg.debug(this, "  key[" + i + "].minKey = 0x" + Long.toHexString(key));
					Msg.debug(this,
						"  key[" + (i - 1) + "].minKey = 0x" + Long.toHexString(prevKey));
				}
			}
			prevKey = key;
		}

		if ((parent == null || parent.isLeftmostKey(getKey(0))) && getPreviousLeaf() != null) {
			consistent = false;
			logConsistencyError(tableName, "previous-leaf should not exist", null);
		}

		LongKeyRecordNode node = getNextLeaf();
		if (node != null) {
			if (parent == null || parent.isRightmostKey(getKey(0))) {
				consistent = false;
				logConsistencyError(tableName, "next-leaf should not exist", null);
			}
			else {
				LongKeyRecordNode me = node.getPreviousLeaf();
				if (me != this) {
					consistent = false;
					logConsistencyError(tableName, "next-leaf is not linked to this leaf", null);
				}
			}
		}
		else if (parent != null && !parent.isRightmostKey(getKey(0))) {
			consistent = false;
			logConsistencyError(tableName, "this leaf is not linked to next-leaf", null);
		}

		return consistent;
	}

	@Override
	LongKeyRecordNode getLeafNode(long key) throws IOException {
		return this;
	}

	/**
	 * Get this leaf node's right sibling
	 * @return this leaf node's right sibling or null if right sibling does not exist.
	 * @throws IOException thrown if an IO error occurs
	 */
	LongKeyRecordNode getNextLeaf() throws IOException {
		LongKeyRecordNode leaf = null;
		int nextLeafId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (nextLeafId >= 0) {
			leaf = (LongKeyRecordNode) nodeMgr.getLongKeyNode(nextLeafId);
		}
		return leaf;
	}

	/**
	 * Get this leaf node's left sibling
	 * @return this leaf node's left sibling or null if left sibling does not exist.
	 * @throws IOException thrown if an IO error occurs
	 */
	LongKeyRecordNode getPreviousLeaf() throws IOException {
		LongKeyRecordNode leaf = null;
		int nextLeafId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		if (nextLeafId >= 0) {
			leaf = (LongKeyRecordNode) nodeMgr.getLongKeyNode(nextLeafId);
		}
		return leaf;
	}

	/**
	 * Perform a binary search to locate the specified key.
	 * @param key key value
	 * @return int key index if found, else -(key index + 1) indicates insertion
	 * point.
	 */
	int getKeyIndex(long key) {

		int min = 0;
		int max = keyCount - 1;

		while (min <= max) {
			int i = (min + max) / 2;
			long k = getKey(i);
			if (k == key) {
				return i;
			}
			else if (k < key) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return -(min + 1);
	}

	@Override
	public int getKeyIndex(Field key) throws IOException {
		return getKeyIndex(key.getLongValue());
	}

	/**
	 * Split this leaf node in half and update tree.
	 * When a split is performed, the next operation must be performed
	 * from the root node since the tree may have been restructured.
	 * @return root node which may have changed.
	 * @throws IOException thrown if an IO error occurs
	 */
	LongKeyNode split() throws IOException {

		// Create new leaf
		int oldSiblingId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		LongKeyRecordNode newLeaf = createNewLeaf(buffer.getId(), oldSiblingId);
		DataBuffer newBuf = newLeaf.buffer;
		int newBufId = newBuf.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		if (oldSiblingId >= 0) {
			LongKeyRecordNode leaf = (LongKeyRecordNode) nodeMgr.getLongKeyNode(oldSiblingId);
			leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		// Split node creating two balanced leaves
		splitData(newLeaf);

		if (parent != null) {
			// Ask parent to insert new node and return root
			return parent.insert(newBufId, newLeaf.getKey(0));
		}

		// New parent node becomes root
		return new LongKeyInteriorNode(nodeMgr, getKey(0), buffer.getId(), newLeaf.getKey(0),
			newBufId);
	}

	/**
	 * Append a leaf which contains one or more keys and update tree.  Leaf is inserted
	 * as the new right sibling of this leaf.
	 * @param leaf new right sibling leaf (must be same node type as this leaf)
	 * @return root node which may have changed.
	 * @throws IOException thrown if an IO error occurs
	 */
	LongKeyNode appendLeaf(LongKeyRecordNode leaf) throws IOException {

		// Create new leaf and link
		leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, buffer.getId());
		int rightLeafBufId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		leaf.buffer.putInt(NEXT_LEAF_ID_OFFSET, rightLeafBufId);

		// Adjust this node
		int newBufId = leaf.buffer.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		// Adjust old right node if present
		if (rightLeafBufId >= 0) {
			LongKeyNode rightLeaf = nodeMgr.getLongKeyNode(rightLeafBufId);
			rightLeaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		if (parent != null) {
			// Ask parent to insert new node and return root - leaf parent is unknown
			return parent.insert(newBufId, leaf.getKey(0));
		}

		// New parent node becomes root
		return new LongKeyInteriorNode(nodeMgr, getKey(0), buffer.getId(), leaf.getKey(0),
			newBufId);
	}

	/**
	 * Remove this leaf from the tree.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyNode removeLeaf() throws IOException {

		long key = getKey(0);
		int prevBufferId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		int nextBufferId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (prevBufferId >= 0) {
			LongKeyRecordNode prevNode = (LongKeyRecordNode) nodeMgr.getLongKeyNode(prevBufferId);
			prevNode.getBuffer().putInt(NEXT_LEAF_ID_OFFSET, nextBufferId);
		}
		if (nextBufferId >= 0) {
			LongKeyRecordNode nextNode = (LongKeyRecordNode) nodeMgr.getLongKeyNode(nextBufferId);
			nextNode.getBuffer().putInt(PREV_LEAF_ID_OFFSET, prevBufferId);
		}

		nodeMgr.deleteNode(this);
		if (parent == null) {
			return null;
		}
		return parent.deleteChild(key);
	}

	/**
	 * Split the contents of this leaf node; placing the right half of the records into the
	 * empty leaf node provided.
	 * @param newRightLeaf empty right sibling leaf
	 */
	abstract void splitData(LongKeyRecordNode newRightLeaf);

	/**
	 * Create a new leaf and add to the node manager.
	 * The new leaf's parent is unknown.
	 * @param prevNodeId node buffer id for previous leaf - left sibling ( &lt; 0: no leaf)
	 * @param nextNodeId node buffer id for next leaf - right sibling ( &lt; 0 : no leaf)
	 * @return new leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract LongKeyRecordNode createNewLeaf(int prevNodeId, int nextNodeId) throws IOException;

	/**
	 * Insert or Update a record.
	 * @param record data record with long key
	 * @param table table which will be notified when record is inserted or updated.
	 * This must be specified when table has indexed columns.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyNode putRecord(DBRecord record, Table table) throws IOException {

		long key = record.getKey();
		int index = getKeyIndex(key);

		// Handle record update case
		if (index >= 0) {
			if (table != null) {
				// update index tables associated with table
				table.updatedRecord(getRecord(table.getSchema(), index), record);
			}
			LongKeyNode newRoot = updateRecord(index, record);
			return newRoot;
		}

		// Handle new record - see if we have room in this leaf
		index = -index - 1;
		if (insertRecord(index, record)) {
			if (index == 0 && parent != null) {
				parent.keyChanged(getKey(1), key);
			}
			if (table != null) {
				// update index tables associated with table
				table.insertedRecord(record);
			}
			return getRoot();
		}

		// Special Case - append new leaf to right
		if (index == keyCount) {
			LongKeyNode newRoot = appendNewLeaf(record);
			if (table != null) {
				// update index tables associated with table
				table.insertedRecord(record);
			}
			return newRoot;
		}

		// Split leaf and complete insertion
		LongKeyRecordNode leaf = split().getLeafNode(key);
		return leaf.putRecord(record, table);
	}

	/**
	 * Append a new leaf and insert the specified record.
	 * @param record data record with long key
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyNode appendNewLeaf(DBRecord record) throws IOException {
		LongKeyRecordNode newLeaf = createNewLeaf(-1, -1);
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
	LongKeyNode deleteRecord(long key, Table table) throws IOException {

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
			LongKeyNode newRoot = removeLeaf();
			return newRoot;
		}

		// Remove record within this node
		remove(index);

		// Notify parent of leftmost key change
		if (index == 0 && parent != null) {
			parent.keyChanged(key, getKey(0));
		}

		return getRoot();
	}

	/**
	 * Remove the record identified by index.
	 * This will never be the last record within the node.
	 * @param index record index
	 * @throws IOException thrown if IO error occurs
	 */
	abstract void remove(int index) throws IOException;

	/**
	 * Inserts the record at the given index if there is sufficient space in
	 * the buffer.
	 * @param index insertion index
	 * @param record record to be inserted
	 * @return true if the record was successfully inserted.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract boolean insertRecord(int index, DBRecord record) throws IOException;

	/**
	 * Updates the record at the given index.
	 * @param index record index
	 * @param record new record
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract LongKeyNode updateRecord(int index, DBRecord record) throws IOException;

	/**
	 * Get the record identified by the specified key.
	 * @param key record key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBRecord getRecord(long key, Schema schema) throws IOException;

	/**
	 * Get the record located at the specified index.
	 * @param schema record data schema
	 * @param index key index
	 * @return Record
	 * @throws IOException thrown if IO error occurs
	 */
	abstract DBRecord getRecord(Schema schema, int index) throws IOException;

	/**
	 * Get the first record whose key is less than the specified key.
	 * @param key record key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordBefore(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -index - 2;
		}
		else {
			--index;
		}
		if (index < 0) {
			LongKeyRecordNode nextLeaf = getPreviousLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, nextLeaf.keyCount - 1) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Get the first record whose key is greater than the specified key.
	 * @param key record key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAfter(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -(index + 1);
		}
		else {
			++index;
		}
		if (index == keyCount) {
			LongKeyRecordNode nextLeaf = getNextLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, 0) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Get the first record whose key is less than or equal to the specified
	 * key.
	 * @param key record key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAtOrBefore(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -index - 2;
		}
		if (index < 0) {
			LongKeyRecordNode nextLeaf = getPreviousLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, nextLeaf.keyCount - 1) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Get the first record whose key is greater than or equal to the specified
	 * key.
	 * @param key record key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAtOrAfter(long key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -(index + 1);
		}
		if (index == keyCount) {
			LongKeyRecordNode nextLeaf = getNextLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, 0) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Create a new record node with no siblings attached.
	 * @param nodeMgr table node manager instance
	 * @param schema record schema
	 * @return new record leaf node
	 * @throws IOException thrown if IO error occurs
	 */
	static LongKeyRecordNode createRecordNode(NodeMgr nodeMgr, Schema schema) throws IOException {
		LongKeyRecordNode node = null;
		if (schema.isVariableLength()) {
			node = new VarRecNode(nodeMgr, -1, -1);
		}
		else {
			node = new FixedRecNode(nodeMgr, schema.getFixedLength(), -1, -1);
		}
		return node;
	}

}
