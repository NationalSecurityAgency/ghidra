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

/**
 * <code>VarKeyNode</code> is an abstract implementation of a BTree node
 * which utilizes variable-length Field key values.
 * <pre>
 *   | NodeType(1) | KeyType(1) | KeyCount(4) | ...
 * </pre>
 */
abstract class VarKeyNode implements FieldKeyNode {

	private static final int KEY_TYPE_SIZE = 1;
	private static final int KEY_COUNT_SIZE = 4;

	private static final int KEY_TYPE_OFFSET = NodeMgr.NODE_HEADER_SIZE;
	private static final int KEY_COUNT_OFFSET = KEY_TYPE_OFFSET + KEY_TYPE_SIZE;

	static final int VARKEY_NODE_HEADER_SIZE =
		NodeMgr.NODE_HEADER_SIZE + KEY_TYPE_SIZE + KEY_COUNT_SIZE;

	protected final Field keyType;
	protected final int maxKeyLength;

	protected NodeMgr nodeMgr;
	protected DataBuffer buffer;
	protected VarKeyInteriorNode parent;
	protected int keyCount;

	/**
	 * Construct an existing variable-length-key node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException if IO error occurs
	 */
	VarKeyNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		this.nodeMgr = nodeMgr;
		this.buffer = buf;
		keyType = Field.getField(buf.getByte(KEY_TYPE_OFFSET));
		keyCount = buffer.getInt(KEY_COUNT_OFFSET);
		maxKeyLength = VarKeyInteriorNode.getMaxKeyLength(buffer.length());
		nodeMgr.addNode(this);
	}

	/**
	 * Construct a new variable-length-key node.
	 * @param nodeMgr table node manager.
	 * @param nodeType node type
	 * @param keyType key Field type
	 * @throws IOException if IO error occurs
	 */
	VarKeyNode(NodeMgr nodeMgr, byte nodeType, Field keyType) throws IOException {
		this.nodeMgr = nodeMgr;
		this.buffer = nodeMgr.getBufferMgr().createBuffer();
		NodeMgr.setNodeType(buffer, nodeType);
		this.keyType = keyType.newField();
		buffer.putByte(KEY_TYPE_OFFSET, keyType.getFieldType());
		setKeyCount(0);
		maxKeyLength = VarKeyInteriorNode.getMaxKeyLength(buffer.length());
		nodeMgr.addNode(this);
	}

	@Override
	public VarKeyInteriorNode getParent() {
		return parent;
	}

	@Override
	public int getBufferId() {
		return buffer.getId();
	}

	@Override
	public DataBuffer getBuffer() {
		return buffer;
	}

	/**
	 * Get the root for this node.  If setParent has not been invoked, this node
	 * is assumed to be the root.
	 * @return TableNode
	 */
	VarKeyNode getRoot() {
		if (parent != null) {
			return parent.getRoot();
		}
		return this;
	}

	@Override
	public int getKeyCount() {
		return keyCount;
	}

	@Override
	public void setKeyCount(int cnt) {
		keyCount = cnt;
		buffer.putInt(KEY_COUNT_OFFSET, keyCount);
	}

	@Override
	public int compareKeyField(Field k, int keyIndex) {
		return k.compareTo(buffer, getKeyOffset(keyIndex));
	}

	/**
	 * Get the key offset within the buffer
	 * @param index key index
	 * @return record key offset
	 */
	public abstract int getKeyOffset(int index);

	/**
	 * Get the key value at a specific index.
	 * @param index key index
	 * @return key value
	 * @throws IOException thrown if an IO error occurs
	 */
	@Override
	public abstract Field getKeyField(int index) throws IOException;

	/**
	 * Get the leaf node which contains the specified key.
	 * @param key key value
	 * @return leaf node
	 * @throws IOException thrown if an IO error occurs
	 */
	@Override
	public abstract VarKeyRecordNode getLeafNode(Field key) throws IOException;

	/**
	 * Get the left-most leaf node within the tree.
	 * @return left-most leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public abstract VarKeyRecordNode getLeftmostLeafNode() throws IOException;

	/**
	 * Get the right-most leaf node within the tree.
	 * @return right-most leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	@Override
	public abstract VarKeyRecordNode getRightmostLeafNode() throws IOException;

}
