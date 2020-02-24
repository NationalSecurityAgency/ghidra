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

/**
 * <code>FieldKeyNode</code> defines a common interface for {@link BTreeNode} 
 * implementations which utilize a {@link Field} key.
 */
interface FieldKeyNode extends BTreeNode {

	/**
	 * @return the parent node or null if this is the root
	 */
	@Override
	public FieldKeyInteriorNode getParent();

	/**
	 * Get the leaf node which contains the specified key.
	 * @param key key value
	 * @return leaf node
	 * @throws IOException thrown if an IO error occurs
	 */
	public FieldKeyRecordNode getLeafNode(Field key) throws IOException;

	/**
	 * Get the left-most leaf node within the tree.
	 * @return left-most leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract FieldKeyRecordNode getLeftmostLeafNode() throws IOException;

	/**
	 * Get the right-most leaf node within the tree.
	 * @return right-most leaf node.
	 * @throws IOException thrown if IO error occurs
	 */
	abstract FieldKeyRecordNode getRightmostLeafNode() throws IOException;

	/**
	 * Performs a fast in-place key comparison of the specified key
	 * value with a key stored within this node at the specified keyIndex.
	 * @param k key value to be compared
	 * @param keyIndex key index to another key within this node's buffer
	 * @return comparison value, zero if equal, -1 if k has a value less than
	 * the store key, or +1 if k has a value greater than the stored key located
	 * at keyIndex.
	 */
	abstract int compareKeyField(Field k, int keyIndex);

}
