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
/*
 * PropertySetPage.java
 *
 * Created on February 20, 2002, 9:30 AM
 */

package ghidra.util.prop;

import ghidra.util.Saveable;
import ghidra.util.datastruct.*;
import ghidra.util.exception.NoValueException;

import java.io.Serializable;

/**
 * Manages property values of type int, String, Object, and
 * "void"  for a page of possible addresses. Void serves as a marker 
 * for whether an address has a property. The derived class for each type holds
 * the actual value of the property, and overrides the
 * appropriate add() and get() methods.
 */
class PropertyPage implements Serializable {
    private final static long serialVersionUID = 1;
    private ShortKeyIndexer indexer;
	private ShortKeySet keySet;	// set of offsets on page having property
	private DataTable table;
	private short pageSize; // valid offsets in range [0,pageSize-1]
    private int switchSize;                                 
    private Class<?> objectClass;
    private NoValueException noValueException;
    private final int threshold; // after number of entries reaches this many,
								 // the data structure for key set switches from
								 // RedBlackKeySet to a BitTree
	/**
	 * Constructor
	 * @param pageSize max number of properties on this page
	 * @param pageID page identifier
	 */
	PropertyPage(short pageSize, long pageID, int valueSize, Class<?> objectClass) {
		keySet = new RedBlackKeySet((short)(pageSize-1));
 		this.pageSize = pageSize;
        this.objectClass = objectClass;
        table = new DataTable();
        indexer = new ShortKeyIndexer();
        
		threshold = pageSize/(RedBlackKeySet.NODESIZE * 4); 
        // 4 is used because a bitTree
		// requires 1/4 the pageSize in bytes.  NODESIZE
		// is the number of bytes in a RedBlackKeySet node.
		// Therefore, to minimize the space used, we should
		// switch to a BitTree when the number of keys exceeds
		// the threshold.
          
        switchSize = (valueSize * pageSize) / (12+valueSize);
        // valueSize * pageSize is the space needed to store a full page
        // of values. 12 is the approximate overhead in a sparce storage
        // structure per entry, make (12 + valueSize) the amount needed per
        // entry.  So when the number of entries is greater than the 
        // switchSize, it is more efficient to just allocate space for
        // the entire page.
        
        noValueException = new NoValueException();
    }
	/**
	 * Returns the next offset after the given offset that has a property
	 *   value.
	 * @param offset offset into the page
	 */
	short getNext(short offset) {
		return keySet.getNext(offset);
	}

	/**
	 * Adds the key to the keySet. If all values are set,
	 * use FullBitSet.
	 * @param key The key to be added to the set.
	 */
	void addKey(short key) {
        if ((keySet.size() == switchSize) && indexer != null) {
            DataTable newTable = new DataTable();
            short oldKey = keySet.getFirst();
            while(oldKey != -1) {
                table.copyRowTo(indexer.get(oldKey), newTable, oldKey);
                oldKey = keySet.getNext(oldKey);
            }
            indexer = null;
            table = newTable;
        }


		if(keySet.size() == threshold) {
			if(keySet instanceof RedBlackKeySet) {
				// switch to BitTree
				BitTree newKeySet = new BitTree((short)(pageSize-1));
				short oldKey = keySet.getFirst();

				while(oldKey != -1) {
					newKeySet.put(oldKey);
					oldKey = keySet.getNext(oldKey);
				}
				keySet = newKeySet;
			}
		}
		keySet.put(key);
        if (keySet.size() == pageSize) {
            // we may already have a FullKeySet
            if(!(keySet instanceof FullKeySet)) {
                keySet = new FullKeySet(pageSize);
            }
        }


	}

    void addKeys(short startKey, short endKey) {
        if ((startKey == 0) && (endKey == pageSize-1)) {
            keySet = new FullKeySet(pageSize);
        }
        else {
            for(short i = startKey;i<=endKey;i++) {
                addKey(i);
            }
        }
    }

	/**
	 * Return the previous offset (before offset) that has a
	 * property.
	 * @param offset offset into the page
	 */
	short getPrevious(short offset) {
		return keySet.getPrevious(offset);
	}

	/**
	 * Return the first offset that has a property.
	 */
	short getFirst() {
		return keySet.getFirst();
	}
	/**
	 * Return the last offset that has a property.
	 */
	short getLast() {
		return keySet.getLast();
	}
	/**
	 * Return whether this page has any offset with
	 * a property.
	 */
	boolean isEmpty() {
		return keySet.isEmpty();
	}
	/**
	 * Return whether the given offset has a property.
	 * @param offset offset into the page
	 */
	boolean hasProperty(short offset) {
		return keySet.containsKey(offset);
	}
    
    private int getRow(short offset, boolean forceRow) {
        if (indexer != null) {
            if (forceRow) {
                return indexer.put(offset);
            }
            return indexer.get(offset);
        }
        return offset;
    }
/////////////////////////////////////////////////////////////////////
	/**
	 * Get the object property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support object values for properties
	 */
	Saveable getSaveableObject(short offset) {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
	
			try {
		        Saveable so = (Saveable)objectClass.newInstance();
		        so.restore(new ObjectStorageAdapter(table, row));  
		        return so;
			}catch(IllegalAccessException e) {
			}catch(InstantiationException e) {
			}
		}
        return null;
    }
	/**
	 * Add the object property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support object values for properties
	 */
	void addSaveableObject(short offset,Saveable value) {
        addKey(offset);
        int row = getRow(offset,true);
		value.save(new ObjectStorageAdapter(table, row));
	}
/////////////////////////////////////////////////////////////////////
	/**
	 * Get the object property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support object values for properties
	 */
	Object getObject(short offset) {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
			return table.getObject(row, 0);	
		}
        return null;
    }
	/**
	 * Add the object property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support object values for properties
	 */
	void addObject(short offset,Object value) {
        addKey(offset);
        int row = getRow(offset,true);
		table.putObject(row, 0, value);
	}
//////////////////////////////////////////////////////////////
	/**
	 * Get the String property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support String values for properties
	 */
	String getString(short offset) {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
	        return table.getString(row,0);
		}
		return null;
    }

	/**
	 * Add the String property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support String values for properties
	 */
	void addString(short offset, String value) {
        addKey(offset);
        int row = getRow(offset,true);
        table.putString(row,0,value);
    }

///////////////////////////////////////////////////////////////
	/**
	 * Get the int property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support int values for properties
	 */
	int getInt(short offset) throws NoValueException {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
        	return table.getInt(row,0);
		}
		throw noValueException;
    }
	/**
	 * Add the int property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support int values for properties
	 */
	void addInt(short offset, int value) {
        addKey(offset);
        int row = getRow(offset,true);
        table.putInt(row,0,value);
        
    }
//////////////////////////////////////////////////////////////    
	/**
	 * Get the long property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support long values for properties
	 */
	long getLong(short offset) throws NoValueException {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
        	return table.getLong(row,0);
		}
		throw noValueException;
    }
	/**
	 * Add the long property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support int values for properties
	 */
	void addLong(short offset, long value) {
        addKey(offset);
        int row = getRow(offset,true);
        table.putLong(row,0,value);
        
    }
    
//////////////////////////////////////////////////////////////    
	/**
	 * Get the short property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support long values for properties
	 */
	short getShort(short offset) throws NoValueException {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
        	return table.getShort(row,0);
		}
		throw noValueException;
    }
	/**
	 * Add the short property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support int values for properties
	 */
	void addShort(short offset, short value) {
        addKey(offset);
        int row = getRow(offset,true);
        table.putShort(row,0,value);
        
    }
    
//////////////////////////////////////////////////////////////    
	/**
	 * Get the long property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support long values for properties
	 */
	byte getByte(short offset) throws NoValueException {
		if (keySet.containsKey(offset)) {
	        int row = getRow(offset,false);
        	return table.getByte(row,0);
		}
		throw noValueException;
    }
	/**
	 * Add the byte property at the given offset.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support int values for properties
	 */
	void addByte(short offset, byte value) {
        addKey(offset);
        int row = getRow(offset,true);
        table.putByte(row,0,value);
        
    }
    
    
///////////////////////////////////////////////////////////////
	/**
	 * Mark the given offset as having a property.
	 * @param offset offset into the page
	 * @exception TypeMismatchException thrown if the page
	 * does not support "void" properties
	 */
	void add(short offset) {
        addKey(offset);
    }

	/**
	 * Mark the given offset ranges as having a property.
	 * @param startOffset first offset.
     * @param endOffset last offset.
	 * @exception TypeMismatchException thrown if the page
	 * does not support "void" properties
	 */
	void addRange(short startOffset, short endOffset) {
        addKeys(startOffset, endOffset);
	}
////////////////////////////////////////////////////////////////
	/**
	 * Get the number of properties on this page.
	 */
    int getSize() {
        return keySet.size();
    }
	/**
	 * Remove the property at the given offset.
	 * @param offset offset into the page
	 * @return true if the property was removed; return false
	 * if there was not a property at offset
	 */
	boolean remove(short offset) {
        if (keySet instanceof FullKeySet) {
            keySet = new BitTree((short)(pageSize-1), true);
        }

		boolean result = keySet.remove(offset);
        if (keySet.size() == 0) {
            keySet = new RedBlackKeySet((short)(pageSize-1));
        }
        int row = getRow(offset,false);
        if (row >= 0) {
	        table.removeRow(row);
        }

        if ((keySet.size() < switchSize/2) && (indexer == null)) {
            DataTable newTable = new DataTable();
            indexer = new ShortKeyIndexer();
            short oldKey = keySet.getFirst();
            while(oldKey != -1) {
                int newRow = indexer.put(oldKey);
                table.copyRowTo(oldKey, newTable, newRow);
				oldKey = keySet.getNext(oldKey);
            }
            table = newTable;
        }
            
        return result;
	}
}
