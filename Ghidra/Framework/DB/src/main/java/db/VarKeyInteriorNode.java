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
 * 
 *   | NodeType(1) | KeyType(1) | KeyCount(4) | KeyOffset0(4) | ID0(4) | ... | KeyOffsetN(4) | IDN(4) | 
 *     ...&lt;FreeSpace&gt;... | KeyN | ... | Key0 |  
 */
class VarKeyInteriorNode extends VarKeyNode implements FieldKeyInteriorNode {

	private static final int BASE = VARKEY_NODE_HEADER_SIZE;

	private static final int KEY_OFFSET_SIZE = 4;  // int
	private static final int ID_SIZE = 4;   // int

	private static final int ENTRY_SIZE = KEY_OFFSET_SIZE + ID_SIZE;

	private static final int MIN_KEY_CAPACITY = 8;
	private static final int HALF_KEY_CAPACITY = MIN_KEY_CAPACITY / 2;

	/**
	 * Construct an existing variable-length-key interior node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException if IO error occurs
	 */
	VarKeyInteriorNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		super(nodeMgr, buf);
	}

	/**
	 * Construct a new variable-length-key interior node with two child nodes.
	 * @param nodeMgr table node manager.
	 * @param key1 left child node left-most key
	 * @param id1 left child node buffer ID
	 * @param key2 right child node left-most key
	 * @param id2 right child node buffer ID
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyInteriorNode(NodeMgr nodeMgr, Field key1, int id1, Field key2, int id2)
			throws IOException {
		super(nodeMgr, NodeMgr.VARKEY_INTERIOR_NODE, key1);

		// Store key and node ids
		insertEntry(0, key1, id1);
		insertEntry(1, key2, id2);
	}

	/**
	 * Construct a new empty variable-length-key interior node.
	 * Node must be initialized with a minimum of two keys.
	 * @param nodeMgr table node manager.
	 * @param keyType sample key Field
	 */
	private VarKeyInteriorNode(NodeMgr nodeMgr, Field keyType) throws IOException {
		super(nodeMgr, NodeMgr.VARKEY_INTERIOR_NODE, keyType);
	}

	void logConsistencyError(String tableName, String msg, Throwable t) throws IOException {
		Msg.debug(this, "Consistency Error (" + tableName + "): " + msg);
		Msg.debug(this, "  parent.key[0]=" + getKeyField(0) + " bufferID=" + getBufferId());
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
				Msg.debug(this,
					"  child[" + i + "].minKey = " + key + " bufferID=" + getBufferId(i));
				Msg.debug(this, "  child[" + (i - 1) + "].minKey = " + lastMinKey + " bufferID=" +
					getBufferId(i - 1));
			}
			else if (lastMaxKey != null && key.compareTo(lastMaxKey) <= 0) {
				consistent = false;
				logConsistencyError(tableName,
					"child[" + i + "].minKey <= child[" + (i - 1) + "].maxKey", null);
				Msg.debug(this,
					"  child[" + i + "].minKey = " + key + " bufferID=" + getBufferId(i));
				Msg.debug(this, "  child[" + (i - 1) + "].maxKey = " + lastMaxKey + " bufferID=" +
					getBufferId(i - 1));
			}

			lastMinKey = key;

			VarKeyNode node = null;
			try {
				try {
					node = nodeMgr.getVarKeyNode(getBufferId(i));
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

				// Verify key match-up between parent and child
				Field childKey0 = node.getKeyField(0);
				if (!key.equals(childKey0)) {
					consistent = false;
					logConsistencyError(tableName,
						"parent key entry mismatch with child[" + i + "].minKey", null);
					Msg.debug(this,
						"  child[" + i + "].minKey = " + childKey0 + " bufferID=" + getBufferId(i));
					Msg.debug(this, "  parent key entry = " + key);
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
	 * Get the maximum number of bytes which may be consumed by a key.
	 * @param bufferLength buffer length
	 * @return maximum length of stored key (this includes the 4-byte length
	 * prefix which is stored with variable length key fields).
	 */
	static int getMaxKeyLength(int bufferLength) {
		return ((bufferLength - BASE) / MIN_KEY_CAPACITY) - ENTRY_SIZE;
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
	 * @throws IOException if IO error occurs
	 */
	int getIdIndex(Field key) throws IOException {

		int min = 1;
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
		return max;
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
	 * Perform a binary search across the stored key offsets to find the
	 * key index which corresponds to the specified key offset.  This facilitates
	 * finding the key which utilizes the buffer storage at the specified 
	 * offset.
	 * @return key index.
	 */
	private int getOffsetIndex(int offset) {

		int min = 0;
		int max = keyCount - 1;

		while (min <= max) {
			int i = (min + max) / 2;
			int keyOff = getKeyOffset(i);
			if (keyOff == offset) {
				return i;
			}
			else if (keyOff < offset) {
				max = i - 1;
			}
			else {
				min = i + 1;
			}
		}
		return min;
	}

	/**
	 * Get the key offset within the buffer
	 * @param index key index
	 * @return record key offset
	 */
	@Override
	public int getKeyOffset(int index) {
		return buffer.getInt(BASE + (index * ENTRY_SIZE));
	}

	/**
	 * Store the key offset within the buffer for the specified key index.
	 * @param index key index
	 * @param offset key offset
	 */
	private void putKeyOffset(int index, int offset) {
		buffer.putInt(BASE + (index * ENTRY_SIZE), offset);
	}

	@Override
	public Field getKeyField(int index) throws IOException {
		Field key = keyType.newField();
		key.read(buffer, buffer.getInt(BASE + (index * ENTRY_SIZE)));
		return key;
	}

	/**
	 * Get the length of a specified child key.
	 * @param index child key index
	 * @return key storage length
	 * @throws IOException thrown if an IO error occurs
	 */
	private int getKeyLength(int index) throws IOException {
		return keyType.readLength(buffer, buffer.getInt(BASE + (index * ENTRY_SIZE)));
	}

	/**
	 * Get the child node buffer ID associated with the specified key index
	 * @param index child key index
	 * @return child node buffer ID
	 */
	private int getBufferId(int index) {
		return buffer.getInt(BASE + (index * ENTRY_SIZE) + KEY_OFFSET_SIZE);
	}

	/**
	 * @return unused free space within node
	 */
	private int getFreeSpace() {
		return (keyCount == 0 ? buffer.length() : getKeyOffset(keyCount - 1)) -
			(keyCount * ENTRY_SIZE) - BASE;
	}

	/**
	 * Insert the child node entry (key and buffer ID) associated with the specified key index.
	 * All entries at and after index are shifted to make space for new entry.
	 * The node key count is adjusted to reflect the addition of a child.
	 * @param index child key index
	 * @param key child node key
	 * @param bufferId child node buffer ID
	 */
	private void insertEntry(int index, Field key, int bufferId) throws IOException {
		// Make room for key data
		int offset = moveKeys(index, -key.length());

		// Make room for key entry
		int start = BASE + (index * ENTRY_SIZE);
		int end = BASE + (keyCount * ENTRY_SIZE);
		buffer.move(start, start + ENTRY_SIZE, end - start);

		// Store key entry and data
		buffer.putInt(start, offset);
		buffer.putInt(start + KEY_OFFSET_SIZE, bufferId);
		key.write(buffer, offset);

		setKeyCount(keyCount + 1);
	}

	/**
	 * Update the child key associated with the specified key index.
	 * Other entries are shifted as necessary to accommodate the new key length for 
	 * the updated entry.
	 * @param index child key index
	 * @param updateKey updated child node key
	 */
	private void updateKey(int index, Field updateKey) throws IOException {

		// Adjust key data space
		int offset = moveKeys(index + 1, getKeyLength(index) - updateKey.length());

		// Update key data
		updateKey.write(buffer, offset);
		putKeyOffset(index, offset);
	}

	/**
	 * Delete the child node entry (key and buffer ID) associated with the specified key index.
	 * Other entries after shifted as necessary.
	 * The node key count is adjusted to reflect the removal of a child.
	 * @param index child key index
	 */
	private void deleteEntry(int index) throws IOException {
		if (keyCount < 3 || index >= keyCount)
			throw new AssertException();
		int moveIndex = index + 1;
		if (moveIndex < keyCount) {

			// Delete key data
			moveKeys(moveIndex, getKeyLength(index));

			// Shift entries
			int start = BASE + (moveIndex * ENTRY_SIZE);
			int end = BASE + (keyCount * ENTRY_SIZE);
			buffer.move(start, start - ENTRY_SIZE, end - start);
		}
		setKeyCount(keyCount - 1);
	}

	/**
	 * Move all keys from index to the end by the specified offset.
	 * @param index the smaller key index (0 &lt;= index1)
	 * @param offset movement offset in bytes
	 * @return insertion offset immediately following moved block. 
	 */
	private int moveKeys(int index, int offset) {

		int lastIndex = keyCount - 1;

		// No movement needed for appended record
		if (index == keyCount) {
			if (index == 0) {
				return buffer.length() + offset;
			}
			return getKeyOffset(lastIndex) + offset;
		}

		// Determine block to be moved
		int start = getKeyOffset(lastIndex);
		int end = (index == 0) ? buffer.length() : getKeyOffset(index - 1);
		int len = end - start;

		// Move record data
		buffer.move(start, start + offset, len);

		// Adjust stored offsets
		for (int i = index; i < keyCount; i++) {
			putKeyOffset(i, getKeyOffset(i) + offset);
		}
		return end + offset;
	}

	/**
	 * Callback method for when a child node's leftmost key changes.
	 * @param oldKey previous leftmost key.
	 * @param newKey new leftmost key.
	 * @param node child node containing oldKey
	 * @throws IOException if IO error occurs
	 */
	@Override
	public void keyChanged(Field oldKey, Field newKey, FieldKeyNode node) throws IOException {

		int index = getKeyIndex(oldKey);
		if (index < 0) {
			throw new AssertException();
		}
		// Is there room for updated key
		int lenChange = newKey.length() - oldKey.length();
		if (lenChange > 0 && lenChange > getFreeSpace()) {
			// Split node if updated key won't fit
			split(index, oldKey, newKey, (VarKeyNode) node);
		}

		else {
			// Update key
			updateKey(index, newKey);

			if (index == 0 && parent != null) {
				parent.keyChanged(oldKey, newKey, this);
			}
		}
	}

	/**
	 * Split this interior node and update the old key entry.
	 * @param oldIndex index of key to be updated
	 * @param oldKey old key value stored at oldIndex
	 * @param newKey new key value
	 * @param node child node containing oldKey
	 * @throws IOException if IO error occurs
	 */
	private void split(int oldIndex, Field oldKey, Field newKey, VarKeyNode node)
			throws IOException {

		// Create new interior node
		VarKeyInteriorNode newNode = new VarKeyInteriorNode(nodeMgr, keyType);

		int halfway =
			((keyCount == 0 ? buffer.length() : getKeyOffset(keyCount - 1)) + buffer.length()) / 2;

		int splitIndex = getOffsetIndex(halfway);
		moveKeysRight(this, newNode, keyCount - splitIndex);

		// Update key entry
		if (splitIndex > oldIndex) {

			// Update key in left node
			updateKey(oldIndex, newKey);

			if (oldIndex == 0 && parent != null) {
				parent.keyChanged(oldKey, newKey, this);
			}

		}
		else {

			// Update key in new right node - node's parent changed
			newNode.updateKey(oldIndex - keyCount, newKey);
			node.parent = newNode;
		}

		if (parent != null) {
			parent.insert(newNode);
			if (newNode.parent != parent) {
				// Fix my parent
				if (parent.getKeyIndex(getKeyField(0)) < 0) {
					parent = newNode.parent;
				}
			}
			return;
		}

		// New parent node becomes root
		parent = new VarKeyInteriorNode(nodeMgr, getKeyField(0), buffer.getId(),
			newNode.getKeyField(0), newNode.getBufferId());
		newNode.parent = parent;
	}

	/**
	 * Insert new child node.
	 * @param node new child node.
	 * @return root node
	 * @throws IOException thrown if IO error occurs
	 */
	VarKeyNode insert(VarKeyNode node) throws IOException {

		Field key = node.getKeyField(0);
		int id = node.getBufferId();

		// Split this node if full
		if ((key.length() + ENTRY_SIZE) > getFreeSpace()) {
			return split(key, id, node);
		}

		return insert(id, key, node);
	}

	/**
	 * Insert a new entry into this node.
	 * It is assumed that there is sufficient space for the new entry.
	 * @param id id of new node
	 * @param key leftmost key associated with new node.
	 * @param node child node which corresponds to the id and key.
	 * @return root node.
	 * @throws IOException thrown if an IO error occurs
	 */
	VarKeyNode insert(int id, Field key, VarKeyNode node) throws IOException {

		// Insert key into this node
		int index = -(getKeyIndex(key) + 1);
		if (index < 0 || id == 0)
			throw new AssertException();
		insertEntry(index, key, id);

		// Set child node's parent
		node.parent = this;

		if (index == 0 && parent != null) {
			parent.keyChanged(getKeyField(1), key, this);
		}

		return getRoot();
	}

	/**
	 * Split this interior node and insert new child entry (key and buffer ID).  
	 * Assumes 3 or more child keys exist in this node.
	 * @param newKey new child key 
	 * @param newId new child node's buffer ID
	 * @param node child node instance (corresponds to newKey and newId)
	 * @return root node.
	 * @throws IOException thrown if IO error occurs
	 */
	private VarKeyNode split(Field newKey, int newId, VarKeyNode node) throws IOException {

		// Create new interior node
		VarKeyInteriorNode newNode = new VarKeyInteriorNode(nodeMgr, keyType);

		int halfway =
			((keyCount == 0 ? buffer.length() : getKeyOffset(keyCount - 1)) + buffer.length()) / 2;

		moveKeysRight(this, newNode, keyCount - getOffsetIndex(halfway));

		// Insert new key/id
		Field rightKey = newNode.getKeyField(0);
		if (newKey.compareTo(rightKey) < 0) {
			insert(newId, newKey, node);
		}
		else {
			newNode.insert(newId, newKey, node);
		}

		if (parent != null) {
			VarKeyNode rootNode = parent.insert(newNode);
			if (newNode.parent != parent) {
				// Fix my parent
				if (parent.getKeyIndex(getKeyField(0)) < 0) {
					parent = newNode.parent;
				}
			}
			return rootNode;
		}

		// New parent node becomes root
		parent = new VarKeyInteriorNode(nodeMgr, getKeyField(0), buffer.getId(), rightKey,
			newNode.getBufferId());
		newNode.parent = parent;
		return parent;
	}

	@Override
	public VarKeyRecordNode getLeafNode(Field key) throws IOException {
		VarKeyNode node = nodeMgr.getVarKeyNode(getBufferId(getIdIndex(key)));
		node.parent = this;
		return node.getLeafNode(key);
	}

	@Override
	public VarKeyRecordNode getLeftmostLeafNode() throws IOException {
		VarKeyNode node = nodeMgr.getVarKeyNode(getBufferId(0));
		return node.getLeftmostLeafNode();
	}

	@Override
	public VarKeyRecordNode getRightmostLeafNode() throws IOException {
		VarKeyNode node = nodeMgr.getVarKeyNode(getBufferId(keyCount - 1));
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
	VarKeyNode deleteChild(Field key) throws IOException {

		int index = getKeyIndex(key);
		if (index < 0)
			throw new AssertException();

		// Handle ellimination of this node
		if (keyCount == 2) {
			if (parent != null)
				throw new AssertException();
			VarKeyNode rootNode = nodeMgr.getVarKeyNode(getBufferId(1 - index));
			rootNode.parent = null;
			nodeMgr.deleteNode(this);
			return rootNode;
		}

		// Delete child entry
		deleteEntry(index);
		if (index == 0 && parent != null) {
			parent.keyChanged(key, getKeyField(0), this);
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
	private VarKeyNode balanceChild(VarKeyInteriorNode node) throws IOException {

		// Do nothing if node more than half full
		if (node.getFreeSpace() < (HALF_KEY_CAPACITY * (maxKeyLength + ENTRY_SIZE))) {
			return getRoot();
		}

		// balance with right sibling except if node corresponds to the right-most 
		// key within this interior node - in that case balance with left sibling.
		int index = getIdIndex(node.getKeyField(0));
		if (index == (keyCount - 1)) {
			return balanceChild((VarKeyInteriorNode) nodeMgr.getVarKeyNode(getBufferId(index - 1)),
				node);
		}
		return balanceChild(node,
			(VarKeyInteriorNode) nodeMgr.getVarKeyNode(getBufferId(index + 1)));
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
	private VarKeyNode balanceChild(VarKeyInteriorNode leftNode, VarKeyInteriorNode rightNode)
			throws IOException {

		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;

		int len = buffer.length();
		int leftKeySpace = len - leftNode.getKeyOffset(leftKeyCount - 1);
		int rightKeySpace = len - rightNode.getKeyOffset(rightKeyCount - 1);
		Field rightKey = rightNode.getKeyField(0);

		// Can right keys fit within left node
		if ((rightKeySpace + (rightKeyCount * ENTRY_SIZE)) <= (len - BASE - leftKeySpace -
			(leftKeyCount * ENTRY_SIZE))) {
			// Right node is elliminated and all entries stored in left node
			moveKeysLeft(leftNode, rightNode, rightKeyCount);
			nodeMgr.deleteNode(rightNode);
			return deleteChild(rightKey);
		}

		boolean balanced = false;
		int halfKeySpace = (leftKeySpace + rightKeySpace) / 2;
		if (halfKeySpace < leftKeySpace) {
			// Attempt to move some keys to the right node
			int index = leftNode.getOffsetIndex(len - halfKeySpace);
			balanced = moveKeysRight(leftNode, rightNode, leftKeyCount - index - 1);
		}
		else {
			// Attempt to move some keys to the left node
			int index = rightNode.getOffsetIndex(len - halfKeySpace);
			balanced = moveKeysLeft(leftNode, rightNode, rightKeyCount - index - 1);
		}
		if (balanced) {
			this.keyChanged(rightKey, rightNode.getKeyField(0), rightNode);
		}
		return getRoot();
	}

	/**
	 * Move some (not all) of the keys from the left node into the right node.
	 * @param leftNode
	 * @param rightNode
	 * @param count
	 * @return true if movement occurred, else false
	 */
	private static boolean moveKeysRight(VarKeyInteriorNode leftNode, VarKeyInteriorNode rightNode,
			int count) {
		if (count <= 0)
			return false;
		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int leftOffset = leftNode.getKeyOffset(leftKeyCount - 1);
		int len = leftNode.getKeyOffset(leftKeyCount - count - 1) - leftOffset;

		// Make room on right for key data
		int rightOffset = rightNode.moveKeys(0, -len);
		int offsetCorrection = rightOffset - leftOffset;

		// Move key data to right node
		rightNode.buffer.copy(rightOffset, leftNode.buffer, leftOffset, len);

		// Move entries to right node
		leftOffset = BASE + ((leftKeyCount - count) * ENTRY_SIZE);
		len = count * ENTRY_SIZE;
		rightNode.buffer.move(BASE, BASE + len, rightKeyCount * ENTRY_SIZE);
		rightNode.buffer.copy(BASE, leftNode.buffer, leftOffset, len);

		// Fix key offsets in right node
		for (int i = 0; i < count; i++) {
			rightNode.putKeyOffset(i, rightNode.getKeyOffset(i) + offsetCorrection);
		}

		leftNode.setKeyCount(leftKeyCount - count);
		rightNode.setKeyCount(rightKeyCount + count);
		return true;
	}

	/**
	 * Move some or all of the keys from the right node into the left node.
	 * If all keys are moved, the caller is responsible for deleting the right
	 * node.
	 * @param leftNode
	 * @param rightNode
	 * @param count
	 */
	private static boolean moveKeysLeft(VarKeyInteriorNode leftNode, VarKeyInteriorNode rightNode,
			int count) {
		if (count <= 0)
			return false;
		int leftKeyCount = leftNode.keyCount;
		int rightKeyCount = rightNode.keyCount;
		int rightOffset = rightNode.getKeyOffset(count - 1);
		int len = rightNode.buffer.length() - rightOffset;
		int leftOffset = leftNode.getKeyOffset(leftKeyCount - 1) - len;

		// Move key data to left node
		leftNode.buffer.copy(leftOffset, rightNode.buffer, rightOffset, len);

		// Move entries to left node
		int elen = count * ENTRY_SIZE;
		leftNode.buffer.copy(BASE + (leftKeyCount * ENTRY_SIZE), rightNode.buffer, BASE, elen);

		// Fix key offsets in left node
		int offsetCorrection = leftOffset - rightOffset;
		int newLeftKeyCount = leftKeyCount + count;
		for (int i = leftKeyCount; i < newLeftKeyCount; i++) {
			leftNode.putKeyOffset(i, leftNode.getKeyOffset(i) + offsetCorrection);
		}

		leftNode.setKeyCount(leftKeyCount + count);
		if (count < rightKeyCount) {
			// Only need to update right node if partial move
			rightNode.moveKeys(count, len);
			rightKeyCount -= count;
			rightNode.buffer.move(BASE + elen, BASE, rightKeyCount * ENTRY_SIZE);
			rightNode.setKeyCount(rightKeyCount);
		}
		return true;
	}

	@Override
	public void delete() throws IOException {

		// Delete all child nodes
		for (int index = 0; index < keyCount; index++) {
			nodeMgr.getVarKeyNode(getBufferId(index)).delete();
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

	public boolean isLeftmostKey(Field key) throws IOException {
		if (getIdIndex(key) == 0) {
			if (parent != null) {
				return parent.isLeftmostKey(key);
			}
			return true;
		}
		return false;
	}

	public boolean isRightmostKey(Field key) throws IOException {
		if (getIdIndex(key) == (keyCount - 1)) {
			if (parent != null) {
				return parent.isRightmostKey(getKeyField(0));
			}
			return true;
		}
		return false;
	}
}
