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
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>FixedKeyInteriorNode</code> stores a BTree node for use as an interior
 * node when searching for Table records within the database.  This type of node
 * has the following layout within a single DataBuffer (field size in bytes,
 * where 'L' is the fixed length of the fixed-length key as specified by 
 * key type in associated Schema):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | Key0(L) | ID0(4) | ... | KeyN(L) | IDN(4) |
 * </pre>  
 */
class FixedKeyInteriorNode extends FixedKeyNode implements FieldKeyInteriorNode {

	private static final int BASE = FIXEDKEY_NODE_HEADER_SIZE;

	private static final int ID_SIZE = 4;   // int

	private final int maxKeyCount;
	private final int entrySize;

	/**
	 * Construct an existing fixed-length key interior node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyInteriorNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		super(nodeMgr, buf);
		entrySize = keySize + ID_SIZE;
		maxKeyCount = (buffer.length() - BASE) / entrySize;
	}

	/**
	 * Construct a new fixed-length key interior node with two child nodes.
	 * @param nodeMgr table node manager.
	 * @param keyType key Field type
	 * @param key1 left child node left-most key
	 * @param id1 left child node buffer ID
	 * @param key2 right child node left-most key
	 * @param id2 right child node buffer ID
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyInteriorNode(NodeMgr nodeMgr, Field keyType, byte[] key1, int id1, byte[] key2, int id2)
			throws IOException {
		super(nodeMgr, NodeMgr.FIXEDKEY_INTERIOR_NODE);
		if (keySize != key1.length || keySize != key2.length) {
			throw new IllegalArgumentException("mismatched fixed-length key sizes");
		}
		entrySize = keySize + ID_SIZE;
		maxKeyCount = (buffer.length() - BASE) / entrySize;
		setKeyCount(2);

		// Store key and node ids
		putEntry(0, key1, id1);
		putEntry(1, key2, id2);
	}

	/**
	 * Construct a new empty fixed-length key interior node.
	 * Node must be initialized with a minimum of two keys.
	 * @param nodeMgr table node manager.
	 * @param keyType key Field type
	 * @throws IOException thrown if IO error occurs
	 */
	private FixedKeyInteriorNode(NodeMgr nodeMgr, Field keyType) throws IOException {
		super(nodeMgr, NodeMgr.FIXEDKEY_INTERIOR_NODE);
		entrySize = keySize + ID_SIZE;
		maxKeyCount = (buffer.length() - BASE) / entrySize;
	}

	void logConsistencyError(String tableName, String msg, Throwable t) {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this, "  parent.key[0]=" + BinaryField.getValueAsString(getKey(0)) +
			" bufferID=" + getBufferId());
		if (t != null) {
			Msg.error(this, "Consistency Error (" + tableName + ")", t);
		}
	}

	@Override
	public boolean isConsistent(String tableName, TaskMonitor monitor)
			throws IOException, CancelledException {
		boolean consistent = true;
		Field lastMinKey = null;
		Field lastMaxKey = null;
		for (int i = 0; i < keyCount; i++) {

			// Compare each key entry with the previous entries key-range
			Field key = getKeyField(i);
			if (lastMinKey != null && key.compareTo(lastMinKey) <= 0) {
				consistent = false;
				logConsistencyError(tableName,
					"child[" + i + "].minKey <= child[" + (i - 1) + "].minKey", null);
				Msg.debug(this, "  child[" + i + "].minKey = " + key.getValueAsString() +
					" bufferID=" + getBufferId(i));
				Msg.debug(this, "  child[" + (i - 1) + "].minKey = " +
					lastMinKey.getValueAsString() + " bufferID=" + getBufferId(i - 1));
			}
			else if (lastMaxKey != null && key.compareTo(lastMaxKey) <= 0) {
				consistent = false;
				logConsistencyError(tableName,
					"child[" + i + "].minKey <= child[" + (i - 1) + "].maxKey", null);
				Msg.debug(this, "  child[" + i + "].minKey = " + key.getValueAsString() +
					" bufferID=" + getBufferId(i));
				Msg.debug(this, "  child[" + (i - 1) + "].maxKey = " +
					lastMaxKey.getValueAsString() + " bufferID=" + getBufferId(i - 1));
			}

			lastMinKey = key;

			FixedKeyNode node = null;
			try {
				try {
					node = nodeMgr.getFixedKeyNode(getBufferId(i));
					node.parent = this;
				}
				catch (IOException e) {
					logConsistencyError(tableName, "failed to fetch child node: " + e.getMessage(),
						e);
				}
				catch (RuntimeException e) {
					logConsistencyError(tableName, "failed to fetch child node: " + e.getMessage(),
						e);
				}

				if (node == null) {
					consistent = false;
					lastMaxKey = key; // for lack of a better solution
					continue; // skip child
				}

				lastMaxKey = node.getKeyField(node.getKeyCount() - 1);

				// Verify key matchup between parent and child
				Field childKey0 = node.getKeyField(0);
				if (!key.equals(childKey0)) {
					consistent = false;
					logConsistencyError(tableName,
						"parent key entry mismatch with child[" + i + "].minKey", null);
					Msg.debug(this, "  child[" + i + "].minKey = " + childKey0.getValueAsString() +
						" bufferID=" + getBufferId(i - 1));
					Msg.debug(this, "  parent key entry = " + key.getValueAsString());
				}

				consistent &= node.isConsistent(tableName, monitor);
				monitor.checkCanceled();
			}
			finally {
				if (node != null) {
					// Release nodes as we go - this is not the norm!
					nodeMgr.releaseReadOnlyNode(node.getBufferId());
				}
			}
		}
		monitor.checkCanceled();
		return consistent;
	}

	/**
	 * Perform a binary search to locate the specified key and derive an index
	 * into the Buffer ID storage.  This method is intended to locate the child
	 * node which contains the specified key.  The returned index corresponds 
	 * to a child's stored buffer/node ID and may correspond to another interior
	 * node or a leaf record node.  Each stored key within this interior node
	 * effectively identifies the maximum key contained within the corresponding
	 * child node.
	 * @param key key to search for
	 * @return int buffer ID index of child node.  An existing positive index
	 * value will always be returned.
	 */
	int getIdIndex(Field key) {

		int min = 1;
		int max = keyCount - 1;

		while (min <= max) {
			int i = (min + max) / 2;
			int c = compareKeyField(key, i);
			if (c == 0) {
				return i;
			}
			else if (c > 0) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return max;
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

	@Override
	byte[] getKey(int index) {
		byte[] key = new byte[keySize];
		buffer.get(BASE + (index * entrySize), key);
		return key;
	}

	@Override
	public int compareKeyField(Field k, int keyIndex) {
		return k.compareTo(buffer, BASE + (keyIndex * entrySize));
	}

	/**
	 * Store a key at the specified index
	 * @param index key index
	 * @param key key value
	 */
	private void putKey(int index, byte[] key) {
		buffer.put(BASE + (index * entrySize), key);
	}

	/**
	 * Get the child node buffer ID associated with the specified key index
	 * @param index child key index
	 * @return child node buffer ID
	 */
	private int getBufferId(int index) {
		return buffer.getInt(BASE + (index * entrySize) + keySize);
	}

	/**
	 * Store the child node entry (key and buffer ID) associated with the specified key index.
	 * The entry at index is overwritten.  Since each entry is a fixed length, movement of
	 * existing entries is not necessary.
	 * @param index child key index
	 * @param key child node key
	 * @param bufferId child node buffer ID
	 */
	private void putEntry(int index, byte[] key, int bufferId) {
		int offset = BASE + (index * entrySize);
		buffer.put(offset, key);
		buffer.putInt(offset + keySize, bufferId);
	}

	/**
	 * Insert the child node entry (key and buffer ID) associated with the specified key index.
	 * All entries at and after index are shifted right to make space for new entry.
	 * The node key count is adjusted to reflect the addition of a child.
	 * @param index child key index
	 * @param key child node key
	 * @param bufferId child node buffer ID
	 */
	private void insertEntry(int index, byte[] key, int bufferId) {

		int start = BASE + (index * entrySize);
		int end = BASE + (keyCount * entrySize);
		buffer.move(start, start + entrySize, end - start);
		buffer.put(start, key);
		buffer.putInt(start + keySize, bufferId);

		setKeyCount(keyCount + 1);
	}

	/**
	 * Delete the child node entry (key and buffer ID) associated with the specified key index.
	 * All entries after index are shifted left.
	 * The node key count is adjusted to reflect the removal of a child.
	 * @param index child key index
	 */
	private void deleteEntry(int index) {

		if (keyCount < 3 || index >= keyCount)
			throw new AssertException();

		++index;
		if (index < keyCount) {
			int start = BASE + (index * entrySize);
			int end = BASE + (keyCount * entrySize);
			buffer.move(start, start - entrySize, end - start);
		}
		setKeyCount(keyCount - 1);
	}

	/**
	 * Callback method for when a child node's leftmost key changes.
	 * @param oldKey previous leftmost key.
	 * @param newKeyData new leftmost key.
	 */
	void keyChanged(Field oldKey, byte[] newKeyData) {

		int index = getKeyIndex(oldKey);
		if (index < 0) {
			throw new AssertException();
		}
		// Update key
		putKey(index, newKeyData);
		if (index == 0 && parent != null) {
			parent.keyChanged(oldKey, newKeyData);
		}
	}

	@Override
	public void keyChanged(Field oldKey, Field newKey, FieldKeyNode childNode) throws IOException {
		keyChanged(oldKey, newKey.getBinaryData());
	}

	/**
	 * Insert a new node into this node.
	 * @param id id of new node
	 * @param key leftmost key associated with new node.
	 * @return root node.
	 * @throws IOException thrown if an IO error occurs
	 */
	FixedKeyNode insert(int id, Field key) throws IOException {

		// Split this node if full
		if (keyCount == maxKeyCount) {
			return split(key, id);
		}

		// Insert key into this node
		int index = -(getKeyIndex(key) + 1);
		if (index < 0 || id == 0)
			throw new AssertException();
		byte[] keyData = key.getBinaryData();
		insertEntry(index, keyData, id);

		if (index == 0 && parent != null) {
			parent.keyChanged(getKeyField(1), keyData);
		}

		return getRoot();
	}

	/**
	 * Split this interior node and insert new child entry (key and buffer ID).  
	 * Assumes 3 or more child keys exist in this node.
	 * @param newKey new child key 
	 * @param newId new child node's buffer ID
	 * @return root node.
	 * @throws IOException thrown if IO error occurs
	 */
	private FixedKeyNode split(Field newKey, int newId) throws IOException {

		// Create new interior node
		FixedKeyInteriorNode newNode = new FixedKeyInteriorNode(nodeMgr, keyType);

		moveKeysRight(this, newNode, keyCount / 2);

		// Insert new key/id
		Field rightKey = newNode.getKeyField(0);
		if (newKey.compareTo(rightKey) < 0) {
			insert(newId, newKey);
		}
		else {
			newNode.insert(newId, newKey);
		}

		if (parent != null) {
			// Ask parent to insert new node and return root
			return parent.insert(newNode.getBufferId(), rightKey);
		}

		// New parent node becomes root
		return new FixedKeyInteriorNode(nodeMgr, keyType, getKey(0), buffer.getId(),
			rightKey.getBinaryData(), newNode.getBufferId());
	}

	@Override
	public FixedKeyRecordNode getLeafNode(Field key) throws IOException {
		FixedKeyNode node = nodeMgr.getFixedKeyNode(getBufferId(getIdIndex(key)));
		node.parent = this;
		return (FixedKeyRecordNode) node.getLeafNode(key);
	}

	@Override
	public FieldKeyRecordNode getLeftmostLeafNode() throws IOException {
		FixedKeyNode node = nodeMgr.getFixedKeyNode(getBufferId(0));
		return node.getLeftmostLeafNode();
	}

	@Override
	public FieldKeyRecordNode getRightmostLeafNode() throws IOException {
		FixedKeyNode node = nodeMgr.getFixedKeyNode(getBufferId(keyCount - 1));
		return node.getRightmostLeafNode();
	}

	/**
	 * Callback method allowing child node to remove itself from parent.
	 * Rebalancing of the tree is performed if the interior node falls 
	 * below the half-full point.
	 * @param key child node key
	 * @return root node
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyNode deleteChild(Field key) throws IOException {

		int index = getKeyIndex(key);
		if (index < 0)
			throw new AssertException();

		// Handle ellimination of this node
		if (keyCount == 2) {
			if (parent != null)
				throw new AssertException();
			FixedKeyNode rootNode = nodeMgr.getFixedKeyNode(getBufferId(1 - index));
			rootNode.parent = null;
			nodeMgr.deleteNode(this);
			return rootNode;
		}

		// Delete child entry
		deleteEntry(index);
		if (index == 0 && parent != null) {
			parent.keyChanged(key, getKey(0));
		}

		return (parent != null) ? parent.balanceChild(this) : this;
	}

	/**
	 * Callback method allowing a child interior node to request balancing of its 
	 * content with its sibling nodes.  Balancing is only done if the specified node 
	 * is half-full or less.
	 * @param node child interior node
	 * @return root node
	 */
	private FixedKeyNode balanceChild(FixedKeyInteriorNode node) throws IOException {

		// Do nothing if node more than half full
		if (node.keyCount > maxKeyCount / 2) {
			return getRoot();
		}

		// balance with right sibling except if node corresponds to the right-most 
		// key within this interior node - in that case balance with left sibling.
		int index = getIdIndex(node.getKeyField(0));
		if (index == (keyCount - 1)) {
			return balanceChild(
				(FixedKeyInteriorNode) nodeMgr.getFixedKeyNode(getBufferId(index - 1)), node);
		}
		return balanceChild(node,
			(FixedKeyInteriorNode) nodeMgr.getFixedKeyNode(getBufferId(index + 1)));
	}

	/**
	 * Balance the entries contained within two adjacent child interior nodes.
	 * One of the two nodes must be half-full or less.
	 * This could result in the removal of a child node if entries will fit within
	 * one node.
	 * @param leftNode left child interior node
	 * @param rightNode right child interior node
	 * @return new root
	 * @throws IOException thrown if an IO error occurs
	 */
	private FixedKeyNode balanceChild(FixedKeyInteriorNode leftNode, FixedKeyInteriorNode rightNode)
			throws IOException {

		Field rightKey = rightNode.getKeyField(0);
		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int newLeftKeyCount = leftKeyCount + rightKeyCount;

		// Can right keys fit within left node
		if (newLeftKeyCount <= maxKeyCount) {
			// Right node is elliminated and all entries stored in left node			
			moveKeysLeft(leftNode, rightNode, rightKeyCount);
			nodeMgr.deleteNode(rightNode);
			return deleteChild(rightKey);
		}

		newLeftKeyCount = newLeftKeyCount / 2;
		if (newLeftKeyCount < leftKeyCount) {
			moveKeysRight(leftNode, rightNode, leftKeyCount - newLeftKeyCount);
		}
		else if (newLeftKeyCount > leftKeyCount) {
			moveKeysLeft(leftNode, rightNode, newLeftKeyCount - leftKeyCount);
		}
		this.keyChanged(rightKey, rightNode.getKey(0));
		return getRoot();
	}

	/**
	 * Move some (not all) of the entries from the left node into the right node.
	 * @param leftNode
	 * @param rightNode
	 * @param count
	 */
	private static void moveKeysRight(FixedKeyInteriorNode leftNode, FixedKeyInteriorNode rightNode,
			int count) {

		if (leftNode.keySize != rightNode.keySize) {
			throw new IllegalArgumentException("mismatched fixed key sizes");
		}
		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int leftOffset = BASE + ((leftKeyCount - count) * leftNode.entrySize);
		int len = count * leftNode.entrySize;
		rightNode.buffer.move(BASE, BASE + len, rightKeyCount * leftNode.entrySize);
		rightNode.buffer.copy(BASE, leftNode.buffer, leftOffset, len);
		leftNode.setKeyCount(leftKeyCount - count);
		rightNode.setKeyCount(rightKeyCount + count);
	}

	/**
	 * Move some or all of the entries from the right node into the left node.
	 * If all keys are moved, the caller is responsible for deleting the right
	 * node.
	 * @param leftNode
	 * @param rightNode
	 * @param count
	 */
	private static void moveKeysLeft(FixedKeyInteriorNode leftNode, FixedKeyInteriorNode rightNode,
			int count) {
		if (leftNode.keySize != rightNode.keySize) {
			throw new IllegalArgumentException("mismatched fixed key sizes");
		}
		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int leftOffset = BASE + (leftKeyCount * leftNode.entrySize);
		int len = count * leftNode.entrySize;
		leftNode.buffer.copy(leftOffset, rightNode.buffer, BASE, len);
		leftNode.setKeyCount(leftKeyCount + count);
		if (count < rightKeyCount) {
			// Only need to update right node if partial move
			rightKeyCount -= count;
			rightNode.buffer.move(BASE + len, BASE, rightKeyCount * leftNode.entrySize);
			rightNode.setKeyCount(rightKeyCount);
		}
	}

	@Override
	public void delete() throws IOException {

		// Delete all child nodes
		for (int index = 0; index < keyCount; index++) {
			nodeMgr.getFixedKeyNode(getBufferId(index)).delete();
		}

		// Remove this node
		nodeMgr.deleteNode(this);
	}

	@Override
	public int[] getBufferReferences() {
		int[] ids = new int[keyCount];
		for (int i = 0; i < keyCount; i++) {
			ids[i] = getBufferId(i);
		}
		return ids;
	}

	boolean isLeftmostKey(Field key) {
		if (getIdIndex(key) == 0) {
			if (parent != null) {
				return parent.isLeftmostKey(key);
			}
			return true;
		}
		return false;
	}

	boolean isRightmostKey(Field key) {
		if (getIdIndex(key) == (keyCount - 1)) {
			if (parent != null) {
				return parent.isRightmostKey(getKeyField(0));
			}
			return true;
		}
		return false;
	}

}
