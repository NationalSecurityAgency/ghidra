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
 * <code>FieldKeyRecordNode</code> defines a common interface for {@link FieldKeyNode} 
 * implementations which are also a {@link RecordNode} (i.e., leaf node).
 */
interface FieldKeyRecordNode extends RecordNode, FieldKeyNode {

	/**
	 * Get the record located at the specified index.
	 * @param schema record data schema
	 * @param index key index
	 * @return Record
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecord(Schema schema, int index) throws IOException;

	/**
	 * Insert or Update a record.
	 * @param record data record with long key
	 * @param table table which will be notified when record is inserted or updated.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	FieldKeyNode putRecord(DBRecord record, Table table) throws IOException;

	/**
	 * Remove the record identified by index.
	 * This will never be the last record within the node.
	 * @param index record index
	 * @throws IOException thrown if IO error occurs
	 */
	void remove(int index) throws IOException;

	/**
	 * Determine if this record node has a right sibling.
	 * @return true if right sibling exists
	 * @throws IOException if IO error occurs
	 */
	boolean hasNextLeaf() throws IOException;

	/**
	 * Get this leaf node's right sibling
	 * @return this leaf node's right sibling or null if right sibling does not exist.
	 * @throws IOException if an IO error occurs
	 */
	FieldKeyRecordNode getNextLeaf() throws IOException;

	/**
	 * Determine if this record node has a left sibling.
	 * @return true if left sibling exists
	 * @throws IOException if IO error occurs
	 */
	boolean hasPreviousLeaf() throws IOException;

	/**
	 * Get this leaf node's left sibling
	 * @return this leaf node's left sibling or null if left sibling does not exist.
	 * @throws IOException if an IO error occurs
	 */
	FieldKeyRecordNode getPreviousLeaf() throws IOException;

	/**
	 * Remove this leaf from the tree.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	FieldKeyNode removeLeaf() throws IOException;

	/**
	 * Delete the record identified by the specified key.
	 * @param key record key
	 * @param table table which will be notified when record is deleted.
	 * @return root node which may have changed.
	 * @throws IOException thrown if IO error occurs
	 */
	FieldKeyNode deleteRecord(Field key, Table table) throws IOException;

	/**
	 * Get the record with the minimum key value which is greater than or equal 
	 * to the specified key.
	 * @param key search key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAtOrAfter(Field key, Schema schema) throws IOException;

	/**
	 * Get the record with the maximum key value which is less than or equal 
	 * to the specified key.
	 * @param key search key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAtOrBefore(Field key, Schema schema) throws IOException;

	/**
	 * Get the record with the minimum key value which is greater than 
	 * the specified key.
	 * @param key search key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordAfter(Field key, Schema schema) throws IOException;

	/**
	 * Get the record with the maximum key value which is less than  
	 * the specified key.
	 * @param key search key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecordBefore(Field key, Schema schema) throws IOException;

	/**
	 * Get the record identified by the specified key.
	 * @param key search key
	 * @param schema record data schema
	 * @return Record requested or null if record not found.
	 * @throws IOException thrown if IO error occurs
	 */
	DBRecord getRecord(Field key, Schema schema) throws IOException;

}
