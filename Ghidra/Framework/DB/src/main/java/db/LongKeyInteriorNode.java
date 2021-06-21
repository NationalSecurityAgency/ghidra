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
 * <code>LongKeyInteriorNode</code> stores a BTree node for use as an interior
 * node when searching for Table records within the database.  This type of node
 * has the following layout within a single DataBuffer (field size in bytes):
 * <pre>
 *   | NodeType(1) | KeyCount(4) | Key0(8) | ID0(4) | ... | KeyN(8) | IDN(4) |
 * </pre>  
 */
class LongKeyInteriorNode extends LongKeyNode implements InteriorNode {

	private static final int BASE = LONGKEY_NODE_HEADER_SIZE;

	private static final int KEY_SIZE = 8;  // long
	private static final int ID_SIZE = 4;   // int

	private static final int ENTRY_SIZE = KEY_SIZE + ID_SIZE;

	private int maxKeyCount;

	/**
	 * Construct an existing long-key interior node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 */
	LongKeyInteriorNode(NodeMgr nodeMgr, DataBuffer buf) {
		super(nodeMgr, buf);
		maxKeyCount = (buffer.length() - BASE) / ENTRY_SIZE;
	}

	/**
	 * Construct a new long-key interior node with two child nodes.
	 * @param nodeMgr table node manager.
	 * @param key1 left child node left-most key
	 * @param id1 left child node buffer ID
	 * @param key2 right child node left-most key
	 * @param id2 right child node buffer ID
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyInteriorNode(NodeMgr nodeMgr, long key1, int id1, long key2, int id2)
			throws IOException {
		super(nodeMgr, NodeMgr.LONGKEY_INTERIOR_NODE);
		maxKeyCount = (buffer.length() - BASE) / ENTRY_SIZE;
		setKeyCount(2);

		// Store key and node ids
		putEntry(0, key1, id1);
		putEntry(1, key2, id2);
	}

	@Override
	public LongKeyInteriorNode getParent() {
		return parent;
	}

	/**
	 * Construct a new empty long-key interior node.
	 * Node must be initialized with a minimum of two keys.
	 * @param nodeMgr table node manager.
	 * @throws IOException thrown if IO error occurs
	 */
	private LongKeyInteriorNode(NodeMgr nodeMgr) throws IOException {
		super(nodeMgr, NodeMgr.LONGKEY_INTERIOR_NODE);
		maxKeyCount = (buffer.length() - BASE) / ENTRY_SIZE;
	}

	void logConsistencyError(String tableName, String msg, Throwable t) {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this,
			"  parent.key[0]=" + Long.toHexString(getKey(0)) + " bufferID=" + getBufferId());
		if (t != null) {
			Msg.error(this, "Consistency Error (" + tableName + ")", t);
		}
	}

	@Override
	public boolean isConsistent(String tableName, TaskMonitor monitor)
			throws IOException, CancelledException {
		boolean consistent = true;
		long lastMinKey = 0;
		long lastMaxKey = 0;
		for (int i = 0; i < keyCount; i++) {

			// Compare each key entry with the previous entries key-range
			long key = getKey(i);
			if (i != 0) {
				if (key <= lastMinKey) {
					consistent = false;
					logConsistencyError(tableName,
						"child[" + i + "].minKey <= child[" + (i - 1) + "].minKey", null);
					Msg.debug(this, "  child[" + i + "].minKey = 0x" + Long.toHexString(key) +
						" bufferID=" + getBufferId(i));
					Msg.debug(this, "  child[" + (i - 1) + "].minKey = 0x" +
						Long.toHexString(lastMinKey) + " bufferID=" + getBufferId(i - 1));
				}
				else if (key <= lastMaxKey) {
					consistent = false;
					logConsistencyError(tableName,
						"child[" + i + "].minKey <= child[" + (i - 1) + "].maxKey", null);
					Msg.debug(this, "  child[" + i + "].minKey = 0x" + Long.toHexString(key) +
						" bufferID=" + getBufferId(i));
					Msg.debug(this, "  child[" + (i - 1) + "].maxKey = 0x" +
						Long.toHexString(lastMaxKey) + " bufferID=" + getBufferId(i - 1));
				}
			}

			lastMinKey = key;

			LongKeyNode node = null;
			try {
				try {
					node = nodeMgr.getLongKeyNode(getBufferId(i));
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

				lastMaxKey = node.getKey(node.getKeyCount() - 1);

				// Verify key matchup between parent and child
				long childKey0 = node.getKey(0);
				if (key != childKey0) {
					consistent = false;
					logConsistencyError(tableName,
						"parent key entry mismatch with child[" + i + "].minKey", null);
					Msg.debug(this, "  child[" + i + "].minKey = 0x" + Long.toHexString(childKey0) +
						" bufferID=" + getBufferId(i - 1));
					Msg.debug(this, "  parent key entry = 0x" + Long.toHexString(key));
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
	int getIdIndex(long key) {

		int min = 1;
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
		return max;
	}

	@Override
	public int getKeyIndex(Field key) throws IOException {
		return getKeyIndex(key.getLongValue());
	}

	/**
	 * Perform a binary search to locate the specified key and derive an index
	 * into the Buffer ID storage.  This method is intended to find the insertion 
	 * index or exact match for a child key.  A negative value will be returned
	 * when an exact match is not found and may be transformed into an 
	 * insertion index (insetIndex = -returnedIndex-1).
	 * @param key key to search for
	 * @return int buffer ID index.
	 */
	private int getKeyIndex(long key) {

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
	long getKey(int index) {
		return buffer.getLong(BASE + (index * ENTRY_SIZE));
	}

	/**
	 * Store a key at the specified index
	 * @param index key index
	 * @param key key value
	 */
	private void putKey(int index, long key) {
		buffer.putLong(BASE + (index * ENTRY_SIZE), key);
	}

	/**
	 * Get the child node buffer ID associated with the specified key index
	 * @param index child key index
	 * @return child node buffer ID
	 */
	private int getBufferId(int index) {
		return buffer.getInt(BASE + (index * ENTRY_SIZE) + KEY_SIZE);
	}

//	/**
//	 * Store the child node buffer ID associated with the specified key index
//	 * @param index child key index
//	 * @param id child node buffer ID
//	 */
//	private void putBufferId(int index, int id) {
//		buffer.putInt(BASE + (index * ENTRY_SIZE) + KEY_SIZE, id);
//	}

	/**
	 * Store the child node entry (key and buffer ID) associated with the specified key index.
	 * The entry at index is overwritten.  Since each entry is a fixed length, movement of
	 * existing entries is not necessary.
	 * @param index child key index
	 * @param key child node key
	 * @param bufferId child node buffer ID
	 */
	private void putEntry(int index, long key, int bufferId) {
		int offset = BASE + (index * ENTRY_SIZE);
		buffer.putLong(offset, key);
		buffer.putInt(offset + KEY_SIZE, bufferId);
	}

	/**
	 * Insert the child node entry (key and buffer ID) associated with the specified key index.
	 * All entries at and after index are shifted right to make space for new entry.
	 * The node key count is adjusted to reflect the addition of a child.
	 * @param index child key index
	 * @param key child node key
	 * @param bufferId child node buffer ID
	 */
	private void insertEntry(int index, long key, int bufferId) {

		int start = BASE + (index * ENTRY_SIZE);
		int end = BASE + (keyCount * ENTRY_SIZE);
		buffer.move(start, start + ENTRY_SIZE, end - start);
		buffer.putLong(start, key);
		buffer.putInt(start + KEY_SIZE, bufferId);

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
			int start = BASE + (index * ENTRY_SIZE);
			int end = BASE + (keyCount * ENTRY_SIZE);
			buffer.move(start, start - ENTRY_SIZE, end - start);
		}
		setKeyCount(keyCount - 1);
	}

	/**
	 * Callback method for when a child node's leftmost key changes.
	 * @param oldKey previous leftmost key.
	 * @param newKey new leftmost key.
	 */
	void keyChanged(long oldKey, long newKey) {

		int index = getKeyIndex(oldKey);
		if (index < 0) {
			throw new AssertException();
		}
		// Update key
		putKey(index, newKey);
		if (index == 0 && parent != null) {
			parent.keyChanged(oldKey, newKey);
		}
	}

	/**
	 * Insert a new node into this node.
	 * @param id id of new node
	 * @param key leftmost key associated with new node.
	 * @return root node.
	 */
	LongKeyNode insert(int id, long key) throws IOException {

		// Split this node if full
		if (keyCount == maxKeyCount) {
			return split(key, id);
		}

		// Insert key into this node
		int index = -(getKeyIndex(key) + 1);
		if (index < 0 || id == 0)
			throw new AssertException();
		insertEntry(index, key, id);

		if (index == 0 && parent != null) {
			parent.keyChanged(getKey(1), key);
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
	private LongKeyNode split(long newKey, int newId) throws IOException {

		// Create new interior node
		LongKeyInteriorNode newNode = new LongKeyInteriorNode(nodeMgr);

		moveKeysRight(this, newNode, keyCount / 2);

		// Insert new key/id
		long rightKey = newNode.getKey(0);
		if (newKey < rightKey) {
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
		return new LongKeyInteriorNode(nodeMgr, getKey(0), buffer.getId(), rightKey,
			newNode.getBufferId());
	}

	@Override
	LongKeyRecordNode getLeafNode(long key) throws IOException {
		LongKeyNode node = nodeMgr.getLongKeyNode(getBufferId(getIdIndex(key)));
		node.parent = this;
		return node.getLeafNode(key);
	}

	/**
	 * Callback method allowing child node to remove itself from parent.
	 * Rebalancing of the tree is performed if the interior node falls 
	 * below the half-full point.
	 * @param key child node key
	 * @return root node
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyNode deleteChild(long key) throws IOException {

		int index = getKeyIndex(key);
		if (index < 0)
			throw new AssertException();

		// Handle ellimination of this node
		if (keyCount == 2) {
			if (parent != null)
				throw new AssertException();
			LongKeyNode rootNode = nodeMgr.getLongKeyNode(getBufferId(1 - index));
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
	private LongKeyNode balanceChild(LongKeyInteriorNode node) throws IOException {

		// Do nothing if node more than half full
		if (node.keyCount > maxKeyCount / 2) {
			return getRoot();
		}

		// balance with right sibling except if node corresponds to the right-most 
		// key within this interior node - in that case balance with left sibling.
		int index = getIdIndex(node.getKey(0));
		if (index == (keyCount - 1)) {
			return balanceChild(
				(LongKeyInteriorNode) nodeMgr.getLongKeyNode(getBufferId(index - 1)), node);
		}
		return balanceChild(node,
			(LongKeyInteriorNode) nodeMgr.getLongKeyNode(getBufferId(index + 1)));
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
	private LongKeyNode balanceChild(LongKeyInteriorNode leftNode, LongKeyInteriorNode rightNode)
			throws IOException {

		long rightKey = rightNode.getKey(0);
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
	private static void moveKeysRight(LongKeyInteriorNode leftNode, LongKeyInteriorNode rightNode,
			int count) {

		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int leftOffset = BASE + ((leftKeyCount - count) * ENTRY_SIZE);
		int len = count * ENTRY_SIZE;
		rightNode.buffer.move(BASE, BASE + len, rightKeyCount * ENTRY_SIZE);
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
	private static void moveKeysLeft(LongKeyInteriorNode leftNode, LongKeyInteriorNode rightNode,
			int count) {

		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int leftOffset = BASE + (leftKeyCount * ENTRY_SIZE);
		int len = count * ENTRY_SIZE;
		leftNode.buffer.copy(leftOffset, rightNode.buffer, BASE, len);
		leftNode.setKeyCount(leftKeyCount + count);
		if (count < rightKeyCount) {
			// Only need to update right node if partial move
			rightKeyCount -= count;
			rightNode.buffer.move(BASE + len, BASE, rightKeyCount * ENTRY_SIZE);
			rightNode.setKeyCount(rightKeyCount);
		}
	}

	@Override
	public void delete() throws IOException {

		// Delete all child nodes
		for (int index = 0; index < keyCount; index++) {
			nodeMgr.getLongKeyNode(getBufferId(index)).delete();
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

	public boolean isLeftmostKey(long key) {
		if (getIdIndex(key) == 0) {
			if (parent != null) {
				return parent.isLeftmostKey(key);
			}
			return true;
		}
		return false;
	}

	public boolean isRightmostKey(long key) {
		if (getIdIndex(key) == (keyCount - 1)) {
			if (parent != null) {
				return parent.isRightmostKey(getKey(0));
			}
			return true;
		}
		return false;
	}

}
