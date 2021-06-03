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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>BTreeNode</code> defines a common interface for all types
 * of BTree nodes.
 */
interface BTreeNode {

	/**
	 * @return the parent node or null if this is the root
	 */
	public InteriorNode getParent();

	/**
	 * @return the data buffer ID associated with this node.
	 */
	public int getBufferId();

	/**
	 * @return the data buffer associated with this node.
	 */
	public DataBuffer getBuffer();

	/**
	 * @return the number of keys contained within this node.
	 */
	public int getKeyCount();

	/**
	 * Set the number of keys contained within this node.
	 * @param cnt key count
	 */
	public void setKeyCount(int cnt);

	/**
	 * Get the key value at a specific index.
	 * @param index key index
	 * @return key value
	 * @throws IOException thrown if an IO error occurs
	 */
	public Field getKeyField(int index) throws IOException;

	/**
	 * Perform a binary search to locate the specified key and derive an index
	 * into the Buffer ID storage.  This method is intended to find the insertion 
	 * index or exact match for a child key.  A negative value will be returned
	 * when an exact match is not found and may be transformed into an 
	 * insertion index (insetIndex = -returnedIndex-1).
	 * @param key key to search for
	 * @return int buffer ID index.
	 * @throws IOException thrown if an IO error occurs
	 */
	public int getKeyIndex(Field key) throws IOException;

	/**
	 * Delete this node and all child nodes.
	 * @throws IOException thrown if IO error occurs
	 */
	public void delete() throws IOException;

	/**
	 * Return all buffer IDs for those buffers which are children
	 * of this buffer.
	 * @return array of buffer IDs
	 */
	public int[] getBufferReferences();

	/**
	 * Check the consistency of this node and all of its children.
	 * @return true if consistency check passed, else false
	 * @param tableName name of table containing this node
	 * @param monitor task monitor
	 * @throws IOException if IO error occured
	 * @throws CancelledException if task cancelled
	 * @{@link ThrowsTag} CancelledException
	 */
	public boolean isConsistent(String tableName, TaskMonitor monitor)
			throws IOException, CancelledException;

}
