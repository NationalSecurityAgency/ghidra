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
 * <code>FixedKeyNode</code> is an abstract implementation of a BTree node
 * which utilizes fixed-length key values.  
 * <pre>
 *   | NodeType(1) | KeyCount(4) | ...
 * </pre>
 */
abstract class FixedKeyNode implements FieldKeyNode {

	private static final int KEY_COUNT_SIZE = 4;
	private static final int KEY_COUNT_OFFSET = NodeMgr.NODE_HEADER_SIZE;

	static final int FIXEDKEY_NODE_HEADER_SIZE = NodeMgr.NODE_HEADER_SIZE + KEY_COUNT_SIZE;

	protected final Field keyType;
	protected final int keySize;

	protected NodeMgr nodeMgr;
	protected DataBuffer buffer;
	protected FixedKeyInteriorNode parent;
	protected int keyCount;

	/**
	 * Construct an existing fixed-length key node.
	 * @param nodeMgr table node manager instance
	 * @param buf node buffer
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyNode(NodeMgr nodeMgr, DataBuffer buf) throws IOException {
		this.nodeMgr = nodeMgr;
		buffer = buf;
		Schema schema = nodeMgr.getTableSchema();
		if (!schema.useFixedKeyNodes()) {
			throw new AssertException("unsupported schema");
		}
		keyType = schema.getKeyFieldType();
		keySize = keyType.length();
		keyCount = buffer.getInt(KEY_COUNT_OFFSET);
		nodeMgr.addNode(this);
	}

	/**
	 * Construct a new fixed-length key node.
	 * @param nodeMgr table node manager.
	 * @param nodeType node type
	 * @throws IOException thrown if IO error occurs
	 */
	FixedKeyNode(NodeMgr nodeMgr, byte nodeType) throws IOException {
		this.nodeMgr = nodeMgr;
		buffer = nodeMgr.getBufferMgr().createBuffer();
		NodeMgr.setNodeType(buffer, nodeType);
		Schema schema = nodeMgr.getTableSchema();
		if (!schema.useFixedKeyNodes()) {
			throw new AssertException("unsupported schema");
		}
		keyType = schema.getKeyFieldType();
		keySize = keyType.length();
		setKeyCount(0);
		nodeMgr.addNode(this);
	}

	@Override
	public FixedKeyInteriorNode getParent() {
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
	 * @return root node
	 */
	FixedKeyNode getRoot() {
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

	/**
	 * Get the key value at a specific index.
	 * @param index key index
	 * @return key value
	 */
	abstract byte[] getKey(int index);

	@Override
	public final Field getKeyField(int index) {
		Field key = keyType.newField();
		key.setBinaryData(getKey(index));
		return key;
	}

}
