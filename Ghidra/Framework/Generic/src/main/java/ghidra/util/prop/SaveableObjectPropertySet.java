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
package ghidra.util.prop;

import ghidra.util.*;

import java.io.*;

/**
 * Handles general storage and retrieval of saveable objects indexed by long
 * keys.
 *
 */
public class SaveableObjectPropertySet extends PropertySet {
    private final static long serialVersionUID = 1;
	/**
	 * Constructor for SaveableObjectPropertySet.
	 * @param name the name associated with this property set.
	 */
	public SaveableObjectPropertySet(String name, Class<?> objectClass) {
		super(name, objectClass);
		if (!Saveable.class.isAssignableFrom(objectClass)) {
			throw new IllegalArgumentException("Class "+objectClass+
							"does not implement the Saveable interface");
		}
		try {
			objectClass.newInstance();
		} catch(Exception e) {
			throw new IllegalArgumentException("Class "+objectClass+
				"must be public and have a public, no args, constructor");
		}
	}

	/**
	 * @see PropertySet#getDataSize()
	 */
	@Override
    public int getDataSize() {
		return 20;
	}

	/**
	 * Stores a saveable object at the given index.  Any object currently at
	 * that index will be replaced by the new object.
	 * @param index the index at which to store the saveable object.
	 * @param value the saveable object to store.
	 */
	public void putObject(long index, Saveable value) {
		PropertyPage page = getOrCreatePage(getPageID(index));
		int n = page.getSize();
		page.addSaveableObject(getPageOffset(index), value);
		numProperties += page.getSize() - n;
	}

	/**
	 * Retrieves the saveable object stored at the given index.
	 * @param index the index at which to retrieve the saveable object.
	 * @return the saveable object stored at the given index or null if no
	 * object is stored at the index.
	 */
	public Saveable getObject(long index) {
		PropertyPage page = getPage(getPageID(index));
		if (page != null) {
			return page.getSaveableObject(getPageOffset(index));
		}
		return null;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.util.prop.PropertySet#moveIndex(long, long)
	 */
	@Override
    protected void moveIndex(long from, long to) {
		Saveable value = getObject(from);
		remove(from);
		putObject(to, value);
	}

	/**
	 * saves the property at the given index to the given output stream.
	 */
	@Override
    protected void saveProperty(ObjectOutputStream oos, long index) throws IOException {
		Saveable obj = getObject(index);
		oos.writeObject(obj.getClass().getName());
		obj.save(new ObjectStorageStreamAdapter(oos));
	}
	/**
	 * restores the property from the input stream to the given index.
	 */
	@Override
    protected void restoreProperty(ObjectInputStream ois, long index)
	 	throws IOException, ClassNotFoundException {
        try {
            String className = (String)ois.readObject();
            Class<?> c = Class.forName(className);	
            Saveable obj = (Saveable)c.newInstance();
            obj.restore(new ObjectStorageStreamAdapter(ois));	
            putObject(index, obj);
        } catch (Exception e) {
        	Msg.showError(this, null, null, null, e);
        } 
	}

	/**
	 * 
	 * @see ghidra.util.prop.PropertySet#applyValue(PropertyVisitor, long)
	 */
	@Override
    public void applyValue(PropertyVisitor visitor, long addr) {
		Saveable obj = getObject(addr);
		if (obj != null) {
			visitor.visit(obj);
		}
	}


}
