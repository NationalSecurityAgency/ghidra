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
package ghidra.util.map;

import java.io.*;

/**
 * Handles general storage and retrieval of object values indexed by long keys.
 * @param <T> object property value type
 */
public class ObjectValueMap<T extends Object> extends ValueMap<T> {

	/**
	 * Constructor for ObjectPropertySet.
	 * @param name the name associated with this property set.
	 */
	public ObjectValueMap(String name) {
		super(name, null);
	}

	/**
	 * @see ValueMap#getDataSize()
	 */
	@Override
    public int getDataSize() {
		return 20;
	}

	/**
	 * Stores an object at the given index.  Any object currently at that index
	 * will be replaced by the new object.
	 * @param index the index at which to store the object.
	 * @param value the object to store.
	 */
	public void putObject(long index, T value) {
		ValueStoragePage<T> page = getOrCreatePage(getPageID(index));
		int n = page.getSize();
		page.addObject(getPageOffset(index), value);
		numProperties += page.getSize() - n;
	}

	/**
	 * Retrieves the object stored at the given index.
	 * @param index the index at which to retrieve the object.
	 * @return the object stored at the given index or null if no object is
	 * stored at the index.
	 */
	public T getObject(long index) {
		ValueStoragePage<T> page = getPage(getPageID(index));
		if (page != null) {
			return page.getObject(getPageOffset(index));
		}
		return null;
	}

	@Override
    protected void moveIndex(long from, long to) {
		T value = getObject(from);
		remove(from);
		putObject(to, value);
	}

	@Override
    protected void saveProperty(ObjectOutputStream oos, long index) throws IOException {
		oos.writeObject(getObject(index));
	}

	@SuppressWarnings("unchecked")
	@Override
    protected void restoreProperty(ObjectInputStream ois, long index)
	 	throws IOException, ClassNotFoundException {

		putObject(index, (T) ois.readObject());
	}

}
