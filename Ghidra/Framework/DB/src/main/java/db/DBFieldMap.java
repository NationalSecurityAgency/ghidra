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

import ghidra.util.LongIterator;

import java.io.IOException;
import java.util.NoSuchElementException;

/**
 * <code>DBFieldMap</code> provides a database-backed map of non-unique Field values to long values.
 */
public class DBFieldMap {

	private static final Class<?>[] fieldClasses = {
	};
	
	private static final String[] fieldNames = {
	};
	
	private static final int BUFFER_SIZE = 16 * 1024;
		
	private DBHandle dbh;
	private Schema schema;
	private Table indexTable;
	private Class<? extends Field> fieldClass;
	
	/**
	 * Construct a new map.
	 * A temporary database is used to provide storage for the map.
	 * @param fieldClass specifies class of Field values to be stored in this map.  
	 * @param cacheSizeMB size of data cache in MBytes.
	 */
	public DBFieldMap(Class<? extends Field> fieldClass, int cacheSizeMB) {
		
		if (!Field.class.isAssignableFrom(fieldClass)) {
			throw new IllegalArgumentException("Field class expected");	
		}

		this.fieldClass = fieldClass;
		int indexFieldType;
		try {
			indexFieldType = Field.INDEX_TYPE_FLAG | 
				fieldClass.newInstance().getFieldType();
		} catch (Exception e) {
			throw new IllegalArgumentException("Bad Field class: " + e.getMessage());	
		}
		Field indexKeyField = IndexField.getIndexField((byte)indexFieldType);
		schema = new Schema(0, indexKeyField.getClass(), "MapKey", fieldClasses, fieldNames);
		
		boolean success = false;
		try {
			dbh = new DBHandle(BUFFER_SIZE, cacheSizeMB * 1024 * 1024);
			long txId = dbh.startTransaction();
			indexTable = dbh.createTable("DBFieldMap", schema);
			dbh.endTransaction(txId, true);
			success = true;
		}
		catch (IOException e) {
			throw new RuntimeException(e);	
		}
		finally {
			if (!success && dbh != null) {
				dbh.close();
				dbh = null;	
			}	
		}
		
	}
	
	/**
	 * Dispose all resources associated with this map.
	 * This method should be invoked when the map is no longer needed.
	 */
	public void dispose() {
		if (dbh != null) {
			dbh.close();
			dbh = null;
		}
	}
	
	/*
	 * @see java.lang.Object#finalize()
	 */
	@Override
    protected void finalize() throws Throwable {
		dispose();
	}
	
	/**
	 * Add the specified value pair to this map.
	 * If the entry already exists, this method has no affect.
	 * @param fieldValue
	 * @param longValue
	 */
	public void addEntry(Field fieldValue, long longValue) {
		if (!fieldClass.isInstance(fieldValue)) {
			throw new IllegalArgumentException("Instance of " + fieldClass.getName() + " expected");
		}
		IndexField indexField = IndexField.getIndexField(fieldValue, longValue);
		Record rec = schema.createRecord(indexField);
		try {
			long txId = dbh.startTransaction();
			indexTable.putRecord(rec);
			dbh.endTransaction(txId, true);
		} catch (IOException e) {
			throw new RuntimeException(e);	
		} finally {
				
		}
	}
	
	/**
	 * Delete the specified value pair from this map.
	 * @param fieldValue
	 * @param longValue
	 * @return true if entry exists and was deleted
	 */
	public boolean deleteEntry(Field fieldValue, long longValue) {
		if (!fieldClass.isInstance(fieldValue)) {
			throw new IllegalArgumentException("Instance of " + fieldClass.getName() + " expected");
		}
		IndexField indexField = IndexField.getIndexField(fieldValue, longValue);
		try {
			long txId = dbh.startTransaction();
			boolean success = indexTable.deleteRecord(indexField);
			dbh.endTransaction(txId, true);
			return success;
		} catch (IOException e) {
			throw new RuntimeException(e);	
		}
	}
	
	/**
	 * Determine if the specified value pair exists within this map.
	 * (This method provided for test purposes).
	 * @param fieldValue
	 * @param longValue
	 * @return
	 */
	boolean hasEntry(Field fieldValue, long longValue) {
		if (!fieldClass.isInstance(fieldValue)) {
			throw new IllegalArgumentException("Instance of " + fieldClass.getName() + " expected");
		}
		IndexField indexField = IndexField.getIndexField(fieldValue, longValue);
		try {
			return indexTable.hasRecord(indexField);
		} catch (IOException e) {
			throw new RuntimeException(e);	
		}
	}
	
	public LongIterator iterator() {
		return new MapLongIterator();
	}
	
	private class MapLongIterator implements LongIterator {
		
		DBFieldIterator indexIterator;
		
		MapLongIterator() {
			try {
				indexIterator = indexTable.fieldKeyIterator();
			} catch (IOException e) {
				throw new RuntimeException(e);	
			}
		}

		/*
		 * @see ghidra.util.LongIterator#hasNext()
		 */
		public boolean hasNext() {
			try {
				return indexIterator.hasNext();
			} catch (IOException e) {
				throw new RuntimeException(e);	
			}
		}

		/*
		 * @see ghidra.util.LongIterator#next()
		 */
		public long next() {
			try {
				IndexField indexField = (IndexField) indexIterator.next();
				if (indexField == null) {
					throw new NoSuchElementException();
				}
				return indexField.getPrimaryKey();
				
			} catch (IOException e) {
				throw new RuntimeException(e);	
			}
		}

		/*
		 * @see ghidra.util.LongIterator#hasPrevious()
		 */
		public boolean hasPrevious() {
			try {
				return indexIterator.hasPrevious();
			} catch (IOException e) {
				throw new RuntimeException(e);	
			}
		}

		/*
		 * @see ghidra.util.LongIterator#previous()
		 */
		public long previous() {
			try {
				IndexField indexField = (IndexField) indexIterator.previous();
				if (indexField == null) {
					throw new NoSuchElementException();
				}
				return indexField.getPrimaryKey();
				
			} catch (IOException e) {
				throw new RuntimeException(e);	
			}
		}

	}

}
