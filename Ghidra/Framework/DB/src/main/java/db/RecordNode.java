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
 * {@link Table} record leaf nodes within the BTree structure.
 */
public interface RecordNode extends BTreeNode {

	/**
	 * Get the record offset within the node's data buffer
	 * @param index key/record index
	 * @return positive record offset within buffer, or a negative bufferID for
	 * indirect record storage in a dedicated buffer
	 * @throws IOException if IO error occurs
	 */
	int getRecordOffset(int index) throws IOException;

	/**
	 * Get the key offset within the node's data buffer
	 * @param index key/record index
	 * @return positive record offset within buffer
	 * @throws IOException if IO error occurs
	 */
	int getKeyOffset(int index) throws IOException;

}
