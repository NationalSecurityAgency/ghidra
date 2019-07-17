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


import java.io.IOException;

import db.buffers.DataBuffer;

/**
 * <code>IndexBuffer</code> stores index data for a common index key
 * within a data buffer. The index data has the following layout (field size in
 * bytes):
 * <pre>
 *   | FieldType(1) | KeyCount(4) | PrimeKey1(8) | ... | PrimeKeyN(8) |
 * </pre>
 * This type of index buffer is used to store primary keys associated with a 
 * single secondary key.  The association to a specific secondary key 
 * is handled by the <code>IndexTable</code>.  The primary keys are maintained 
 * within the buffer in an asscending sorted order.
 */
class IndexBuffer {
	
	private static final int FIELD_TYPE_SIZE = 1;
	private static final int KEY_COUNT_SIZE = 4;
	
	private static final int FIELD_TYPE_OFFSET = 0;
	private static final int KEY_COUNT_OFFSET = FIELD_TYPE_OFFSET + FIELD_TYPE_SIZE;
	
	static final int INDEX_HEADER_SIZE = FIELD_TYPE_SIZE + KEY_COUNT_SIZE;
	
	static final int PRIMARY_KEY_SIZE = 8;
	
	Field indexKey;
	int keyCount;
	IndexDataBuffer dataBuffer;
	
	/**
	 * Construct a new index buffer.
	 * @param indexKey associated index key
	 * @param data existing index buffer data from storage or null for an
	 * empty index buffer.
	 * @throws IOException thrown if IO error occurs
	 */
	IndexBuffer(Field indexKey, byte[] data) throws IOException {
		this.indexKey = indexKey;
		if (data == null) {
			dataBuffer = new IndexDataBuffer(INDEX_HEADER_SIZE);
			dataBuffer.putByte(FIELD_TYPE_OFFSET, indexKey.getFieldType());
			dataBuffer.putInt(KEY_COUNT_OFFSET, 0);
		}
		else {
			if (data[FIELD_TYPE_OFFSET] != indexKey.getFieldType())
				throw new IOException("Invalid index data");
			dataBuffer = new IndexDataBuffer(data);
		}	
		keyCount = dataBuffer.getInt(KEY_COUNT_OFFSET);
	}
	
	/**
	 * Get the associated index key
	 * @return index key
	 */
	Field getIndexKey() {
		return indexKey;
	}
	
	/**
	 * Set the stored primary key count
	 * @param cnt primary key count
	 */
	private void setKeyCount(int cnt) {
		keyCount = cnt;
		dataBuffer.putInt(KEY_COUNT_OFFSET, keyCount);	
	}
	
	/**
	 * Provides data buffer manipulation for the index data
	 */
	class IndexDataBuffer extends DataBuffer {
		
		/**
		 * Construct an index data buffer.
		 * @see db.buffers.DataBuffer#DataBuffer(byte[])
		 */
		IndexDataBuffer(byte[] data) {
			super(data);
		}
		
		/**
		 * Construct an index data buffer.
		 * @see db.buffers.DataBuffer#DataBuffer(int)
		 */
		IndexDataBuffer(int size) {
			super(size);
		}
		
		/**
		 * Get the storage array associated with this buffer.
		 * @return byte storage array.
		 */
		@Override
        protected byte[] getData() {
			return data;
		}
		
		/**
		 * Get the storage array associated with this buffer.
		 * @return byte storage array.
		 */
		@Override
        protected void setData(byte[] data) {
			this.data = data;
		}
	}
	
	/**
	 * Get the index buffer data.
	 * @return index data or null if index data is empty.
	 */
	byte[] getData() {
		byte[] data = dataBuffer.getData();
		if (data.length <= INDEX_HEADER_SIZE)
			return null;
		return data;
	}

	/**
	 * Get the primary key associated with the specified entry index.
	 * This method does not perform any bounds checking on the index value.
	 * @param index index entry index.
	 * @return primary key associated with entry.
	 */
	long getPrimaryKey(int index) {
		return dataBuffer.getLong(INDEX_HEADER_SIZE + (index * PRIMARY_KEY_SIZE));
	}
	
	/**
	 * Get the secondary key index within the buffer.
	 * @param primaryKey primary key
	 * @return key index if found, else -(key index + 1) indicates insertion
	 * point.
	 */
	int getIndex(long primaryKey) {
		return getKeyIndex(primaryKey);
	}
	
	/**
	 * Perform a binary search to locate the specified primary key.
	 * @param primaryKey primary key
	 * @return key index if found, else -(key index + 1) indicates insertion
	 * point.
	 */
	private int getKeyIndex(long primaryKey) {
		
		int min = 0;
		int max = keyCount - 1;
		
		while (min <= max) {
			int i = (min + max)/2;
			long k = getPrimaryKey(i);
			if (k == primaryKey) {
				return i;
			}
			else if (k < primaryKey) {
				min = i + 1;
			}
			else {
				max = i - 1;
			}
		}
		return -(min+1);
	}
	
	/**
	 * Add a new primary key to this index buffer.
	 * @param primaryKey primary key
	 */
	void addEntry(long primaryKey) {
		int index = getKeyIndex(primaryKey);
		if (index < 0) {
			index = -index-1;
			IndexDataBuffer newDataBuffer = new IndexDataBuffer(dataBuffer.length() + PRIMARY_KEY_SIZE);
			int len = INDEX_HEADER_SIZE + (index * PRIMARY_KEY_SIZE);
			newDataBuffer.copy(0, dataBuffer, 0, len);		
			newDataBuffer.copy(len + PRIMARY_KEY_SIZE, dataBuffer, len, dataBuffer.length() - len);
			newDataBuffer.putLong(len, primaryKey);
			dataBuffer = newDataBuffer;
			setKeyCount(keyCount + 1);
		}
	}

	/**
	 * Delete the specified index entry from this index buffer.
	 * @param primaryKey primary key
	 */
	void deleteEntry(long primaryKey) {
		int index = getKeyIndex(primaryKey);
		if (index >= 0) {
			IndexDataBuffer newDataBuffer = new IndexDataBuffer(dataBuffer.length() - PRIMARY_KEY_SIZE);
			int len = INDEX_HEADER_SIZE + (index * PRIMARY_KEY_SIZE);
			newDataBuffer.copy(0, dataBuffer, 0, len);		
			newDataBuffer.copy(len, dataBuffer, len + PRIMARY_KEY_SIZE, dataBuffer.length() - len - PRIMARY_KEY_SIZE);
			dataBuffer = newDataBuffer;
			setKeyCount(keyCount - 1);
		}
	}

	/**
	 * Get the list of primary keys contained within this index buffer.
	 * @return long[] list of primary keys
	 * @throws IOException thrown if IO error occurs
	 */
	long[] getPrimaryKeys() {
		long[] keys = new long[keyCount];
		for (int i = 0; i < keyCount; i++) {
			keys[i] = getPrimaryKey(i);
		}
		return keys;
	}


}
