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
 * <code>LongKeyNode</code> is an abstract implementation of a BTree node
 * which utilizes long key values.
 */
abstract class LongKeyNode implements BTreeNode {

	private static final int KEY_COUNT_SIZE = 4;

	private static final int KEY_COUNT_OFFSET = NodeMgr.NODE_HEADER_SIZE;

	static final int LONGKEY_NODE_HEADER_SIZE = NodeMgr.NODE_HEADER_SIZE + KEY_COUNT_SIZE;

	protected NodeMgr nodeMgr;
	protected DataBuffer buffer;
	protected LongKeyInteriorNode parent;
	protected int keyCount;

	/**
	 * Construct an existing long-key node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 */
	LongKeyNode(NodeMgr nodeMgr, DataBuffer buf) {
		this.nodeMgr = nodeMgr;
		this.buffer = buf;
		keyCount = buffer.getInt(KEY_COUNT_OFFSET);
		nodeMgr.addNode(this);
	}

	/**
	 * Construct a new long-key node.
	 * @param nodeMgr table node manager.
	 * @param nodeType node type
	 * @throws IOException thrown if IO error occurs
	 */
	LongKeyNode(NodeMgr nodeMgr, byte nodeType) throws IOException {
		this.nodeMgr = nodeMgr;
		this.buffer = nodeMgr.getBufferMgr().createBuffer();
		NodeMgr.setNodeType(buffer, nodeType);
		setKeyCount(0);
		nodeMgr.addNode(this);
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
	 * @return root node
	 */
	LongKeyNode getRoot() {
		if (parent != null)
			return parent.getRoot();
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

	/**
	 * Get the key value at a specific index.
	 * @param index key index
	 * @return key value
	 */
	abstract long getKey(int index);

	@Override
	public final Field getKeyField(int index) throws IOException {
		return new LongField(getKey(index));
	}

	/**
	 * Get the leaf node which contains the specified key.
	 * @param key key value
	 * @return leaf node
	 * @throws IOException thrown if an IO error occurs
	 */
	abstract LongKeyRecordNode getLeafNode(long key) throws IOException;

}
