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

import java.io.*;

/**
 * Handles general storage and retrieval of Strings indexed by long keys.
 *
 */
public class StringPropertySet extends PropertySet {
    private final static long serialVersionUID = 1;
	/**
	 * Constructor for StringPropertySet.
	 * @param name the name associated with this property set.
	 */
	public StringPropertySet(String name) {
		super(name, null);
	}

	/**
	 * @see PropertySet#getDataSize()
	 */
	@Override
    public int getDataSize() {
		return 8;
	}

	/**
	 * Stores a String at the given index.  Any String currently at that index
	 * will be replaced by the new String.
	 * @param index the index at which to store the String.
	 * @param value the String to store.
	 */
	public void putString(long index, String value) {
		PropertyPage page = getOrCreatePage(getPageID(index));
		int n = page.getSize();
		page.addString(getPageOffset(index), value);
		numProperties += page.getSize() - n;
	}

	/**
	 * Retrieves the String stored at the given index.
	 * @param index the index at which to retrieve the String.
	 * @return the String stored at the given index or null if no String is
	 * stored at that index.
	 */
	public String getString(long index) {
		PropertyPage page = getPage(getPageID(index));
		if (page != null) {
			return page.getString(getPageOffset(index));
		}
		return null;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.util.prop.PropertySet#moveIndex(long, long)
	 */
	@Override
    protected void moveIndex(long from, long to) {
		String value = getString(from);
		remove(from);
		putString(to, value);
	}
	/**
	 * saves the property at the given index to the given output stream.
	 */
	@Override
    protected void saveProperty(ObjectOutputStream oos, long index) throws IOException {
		oos.writeObject(getString(index));
	}
	/**
	 * restores the property from the input stream to the given index.
	 */
	@Override
    protected void restoreProperty(ObjectInputStream ois, long index)
	 	throws IOException, ClassNotFoundException {

		putString(index, (String)ois.readObject());
	}

	/**
	 * 
	 * @see ghidra.util.prop.PropertySet#applyValue(PropertyVisitor, long)
	 */
	@Override
    public void applyValue(PropertyVisitor visitor, long addr) {
		String str = getString(addr);
		if (str != null) {
			visitor.visit(str);
		}
	}


}
