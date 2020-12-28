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
 * <code>FixedKeyRecordNode</code> is an abstract implementation of a BTree leaf node
 * which utilizes fixed-length binary key values and stores records.
 * <p>
 * This type of node has the following partial layout within a single DataBuffer 
 * (field size in bytes):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) ...
 * </pre>
 */
abstract class FixedKeyRecordNode extends FixedKeyNode implements FieldKeyRecordNode {

	private static final int ID_SIZE = 4;

	private static final int PREV_LEAF_ID_OFFSET = FIXEDKEY_NODE_HEADER_SIZE;
	private static final int NEXT_LEAF_ID_OFFSET = PREV_LEAF_ID_OFFSET + ID_SIZE;

	static final int RECORD_LEAF_HEADER_SIZE = FIXEDKEY_NODE_HEADER_SIZE + (2 * ID_SIZE);

	/**
	 * Construct an existing fixed-length key record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException thrown if an IO error occurs
	 */
	FixedKeyRecordNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		super(nodeMgr, buf);
	}

	/**
	 * Construct a new fixed-length key record leaf node.
	 * @param nodeMgr table node manager instance
	 * @param nodeType node type
	 * @param prevLeafId node buffer id for previous leaf - left sibling ( &lt; 0: no leaf)
	 * @param nextLeafId node buffer id for next leaf - right sibling ( &lt; 0 : no leaf)
	 * @throws IOException thrown if an IO error occurs
	 */
	FixedKeyRecordNode(NodeMgr nodeMgr, byte nodeType, int prevLeafId, int nextLeafId)
			throws IOException {
		super(nodeMgr, nodeType);

		// Initialize header
		buffer.putInt(PREV_LEAF_ID_OFFSET, prevLeafId);
		buffer.putInt(NEXT_LEAF_ID_OFFSET, nextLeafId);
	}

	void logConsistencyError(String tableName, String msg, Throwable t) {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this,
			"  bufferID=" + getBufferId() + " key[0]=" + BinaryField.getValueAsString(getKey(0)));
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
			if (prevKey != null && key.compareTo(prevKey) <= 0) {
				consistent = false;
				logConsistencyError(tableName, "key[" + i + "] <= key[" + (i - 1) + "]", null);
				Msg.debug(this, "  key[" + i + "].minKey = " + key.getValueAsString());
				Msg.debug(this, "  key[" + (i - 1) + "].minKey = " + prevKey.getValueAsString());
			}
			prevKey = key;
		}

		Field key0 = getKeyField(0);
		if ((parent == null || parent.isLeftmostKey(key0)) && getPreviousLeaf() != null) {
			consistent = false;
			logConsistencyError(tableName, "previous-leaf should not exist", null);
		}

		FixedKeyRecordNode node = getNextLeaf();
		if (node != null) {
			if (parent == null || parent.isRightmostKey(key0)) {
				consistent = false;
				logConsistencyError(tableName, "next-leaf should not exist", null);
			}
			else {
				FixedKeyRecordNode me = node.getPreviousLeaf();
				if (me != this) {
					consistent = false;
					logConsistencyError(tableName, "next-leaf is not linked to this leaf", null);
				}
			}
		}
		else if (parent != null && !parent.isRightmostKey(key0)) {
			consistent = false;
			logConsistencyError(tableName, "this leaf is not linked to next-leaf", null);
		}

		return consistent;
	}

	@Override
	byte[] getKey(int index) {
		byte[] key = new byte[keySize];
		buffer.get(getKeyOffset(index), key);
		return key;
	}

	@Override
	public int compareKeyField(Field k, int keyIndex) {
		return k.compareTo(buffer, getKeyOffset(keyIndex));
	}

	/**
	 * Get the key offset within the node's data buffer
	 * @param index key/record index
	 * @return positive record offset within buffer
	 */
	@Override
	public abstract int getKeyOffset(int index);

	@Override
	public FixedKeyRecordNode getLeafNode(Field key) throws IOException {
		return this;
	}

	@Override
	public FixedKeyRecordNode getLeftmostLeafNode() throws IOException {
		FixedKeyRecordNode leaf = getPreviousLeaf();
		return leaf != null ? leaf.getLeftmostLeafNode() : this;
	}

	@Override
	public FixedKeyRecordNode getRightmostLeafNode() throws IOException {
		FixedKeyRecordNode leaf = getNextLeaf();
		return leaf != null ? leaf.getRightmostLeafNode() : this;
	}

	@Override
	public boolean hasNextLeaf() throws IOException {
		int nextLeafId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		return (nextLeafId >= 0);
	}

	@Override
	public FixedKeyRecordNode getNextLeaf() throws IOException {
		FixedKeyRecordNode leaf = null;
		int nextLeafId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (nextLeafId >= 0) {
			leaf = (FixedKeyRecordNode) nodeMgr.getFixedKeyNode(nextLeafId);
		}
		return leaf;
	}

	@Override
	public boolean hasPreviousLeaf() throws IOException {
		int prevLeafId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		return (prevLeafId >= 0);
	}

	@Override
	public FixedKeyRecordNode getPreviousLeaf() throws IOException {
		FixedKeyRecordNode leaf = null;
		int prevLeafId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		if (prevLeafId >= 0) {
			leaf = (FixedKeyRecordNode) nodeMgr.getFixedKeyNode(prevLeafId);
		}
		return leaf;
	}

	@Override
	public int getKeyIndex(Field key) {

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
	FixedKeyNode split() throws IOException {

		// Create new leaf
		int oldSiblingId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		FixedKeyRecordNode newLeaf = createNewLeaf(buffer.getId(), oldSiblingId);
		DataBuffer newBuf = newLeaf.buffer;
		int newBufId = newBuf.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		if (oldSiblingId >= 0) {
			FixedKeyRecordNode leaf = (FixedKeyRecordNode) nodeMgr.getFixedKeyNode(oldSiblingId);
			leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		// Split node creating two balanced leaves
		splitData(newLeaf);

		if (parent != null) {
			// Ask parent to insert new node and return root
			return parent.insert(newBufId, newLeaf.getKeyField(0));
		}

		// New parent node becomes root
		return new FixedKeyInteriorNode(nodeMgr, keyType, getKey(0), buffer.getId(),
			newLeaf.getKey(0), newBufId);
	}

	/**
	 * Append a leaf which contains one or more keys and update tree.  Leaf is inserted
	 * as the new right sibling of this leaf.
	 * @param leaf new right sibling leaf (must be same node type as this leaf)
	 * @return root node which may have changed.
	 * @throws IOException thrown if an IO error occurs
	 */
	FixedKeyNode appendLeaf(FixedKeyRecordNode leaf) throws IOException {

		// Create new leaf and link
		leaf.buffer.putInt(PREV_LEAF_ID_OFFSET, buffer.getId());
		int rightLeafBufId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		leaf.buffer.putInt(NEXT_LEAF_ID_OFFSET, rightLeafBufId);

		// Adjust this node
		int newBufId = leaf.buffer.getId();
		buffer.putInt(NEXT_LEAF_ID_OFFSET, newBufId);

		// Adjust old right node if present
		if (rightLeafBufId >= 0) {
			FixedKeyNode rightLeaf = nodeMgr.getFixedKeyNode(rightLeafBufId);
			rightLeaf.buffer.putInt(PREV_LEAF_ID_OFFSET, newBufId);
		}

		if (parent != null) {
			// Ask parent to insert new node and return root - leaf parent is unknown
			return parent.insert(newBufId, leaf.getKeyField(0));
		}

		// New parent node becomes root
		return new FixedKeyInteriorNode(nodeMgr, keyType, getKey(0), buffer.getId(), leaf.getKey(0),
			newBufId);
	}

	/**
	 * Remove this leaf from the tree.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public FixedKeyNode removeLeaf() throws IOException {

		Field key = getKeyField(0);
		int prevBufferId = buffer.getInt(PREV_LEAF_ID_OFFSET);
		int nextBufferId = buffer.getInt(NEXT_LEAF_ID_OFFSET);
		if (prevBufferId >= 0) {
			FixedKeyRecordNode prevNode =
				(FixedKeyRecordNode) nodeMgr.getFixedKeyNode(prevBufferId);
			prevNode.getBuffer().putInt(NEXT_LEAF_ID_OFFSET, nextBufferId);
		}
		if (nextBufferId >= 0) {
			FixedKeyRecordNode nextNode =
				(FixedKeyRecordNode) nodeMgr.getFixedKeyNode(nextBufferId);
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
	abstract void splitData(FixedKeyRecordNode newRightLeaf);

	/**
	 * Create a new leaf and add to the node manager.
	 * The new leaf's parent is unknown.
	 * @param prevNodeId node buffer id for previous leaf - left sibling ( &lt; 0: no leaf)
	 * @param nextNodeId node buffer id for next leaf - right sibling ( &lt; 0 : no leaf)
	 * @return new leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract FixedKeyRecordNode createNewLeaf(int prevNodeId, int nextNodeId) throws IOException;

	@Override
	public FixedKeyNode putRecord(DBRecord record, Table table) throws IOException {

		Field key = record.getKeyField();
		int index = getKeyIndex(key);

		// Handle record update case
		if (index >= 0) {
			if (table != null) {
				table.updatedRecord(getRecord(table.getSchema(), index), record);
			}
			FixedKeyNode newRoot = updateRecord(index, record);
			return newRoot;
		}

		// Handle new record - see if we have room in this leaf
		index = -index - 1;
		if (insertRecord(index, record)) {
			if (index == 0 && parent != null) {
				parent.keyChanged(getKeyField(1), key, null);
			}
			if (table != null) {
				table.insertedRecord(record);
			}
			return getRoot();
		}

		// Special Case - append new leaf to right
		if (index == keyCount) {
			FixedKeyNode newRoot = appendNewLeaf(record);
			if (table != null) {
				table.insertedRecord(record);
			}
			return newRoot;
		}

		// Split leaf and complete insertion
		FixedKeyRecordNode leaf = (FixedKeyRecordNode) split().getLeafNode(key);
		return leaf.putRecord(record, table);
	}

	/**
	 * Append a new leaf and insert the specified record.
	 * @param record data record with long key
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyNode appendNewLeaf(DBRecord record) throws IOException {
		FixedKeyRecordNode newLeaf = createNewLeaf(-1, -1);
		newLeaf.insertRecord(0, record);
		return appendLeaf(newLeaf);
	}

	@Override
	public FieldKeyNode deleteRecord(Field key, Table table) throws IOException {

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
			FixedKeyNode newRoot = removeLeaf();
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
	abstract FixedKeyNode updateRecord(int index, DBRecord record) throws IOException;

	@Override
	public db.DBRecord getRecordBefore(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -index - 2;
		}
		else {
			--index;
		}
		if (index < 0) {
			FixedKeyRecordNode nextLeaf = getPreviousLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, nextLeaf.keyCount - 1) : null;
		}
		return getRecord(schema, index);
	}

	@Override
	public db.DBRecord getRecordAfter(Field key, Schema schema) throws IOException {
		int index = getKeyIndex(key);
		if (index < 0) {
			index = -(index + 1);
		}
		else {
			++index;
		}
		if (index == keyCount) {
			FixedKeyRecordNode nextLeaf = getNextLeaf();
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
			FixedKeyRecordNode nextLeaf = getPreviousLeaf();
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
			FixedKeyRecordNode nextLeaf = getNextLeaf();
			return nextLeaf != null ? nextLeaf.getRecord(schema, 0) : null;
		}
		return getRecord(schema, index);
	}

	/**
	 * Create a new record node with no siblings attached.
	 * @param nodeMgr table node manager instance
	 * @return new record leaf node
	 * @throws IOException thrown if IO error occurs
	 */
	static FixedKeyRecordNode createRecordNode(NodeMgr nodeMgr) throws IOException {
		Schema schema = nodeMgr.getTableSchema();
		FixedKeyRecordNode node = null;
		if (schema.isVariableLength()) {
			node = new FixedKeyVarRecNode(nodeMgr, -1, -1);
		}
		else {
			node = new FixedKeyFixedRecNode(nodeMgr, -1, -1);
		}
		return node;
	}

}
