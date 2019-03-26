/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

import db.buffers.DataBuffer;

/**
 * <code>BTreeNode</code> defines a common interface for all types
 * of BTree nodes.
 */
interface BTreeNode {

	/**
	 * Return the data buffer ID associated with this node.
	 */
	public int getBufferId();

	/**
	 * Return the data buffer associated with this node.
	 */
	public DataBuffer getBuffer();

	/**
	 * Return the number of keys contained within this node.
	 */
	public int getKeyCount();

	/**
	 * Set the number of keys contained within this node.
	 * @param cnt key count
	 */
	public void setKeyCount(int cnt);

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
	 * @param monitor
	 * @throws IOException 
	 * @{@link ThrowsTag} CancelledException
	 */
	public boolean isConsistent(String tableName, TaskMonitor monitor) throws IOException,
			CancelledException;

}
