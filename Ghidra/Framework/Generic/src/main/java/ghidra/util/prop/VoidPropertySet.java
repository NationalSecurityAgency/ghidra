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
 * Handles general storage and retrieval of a void property indexed by long
 * keys.  Void propertys have no value - they either exist or they don't exist.
 *
 */
public class VoidPropertySet extends PropertySet {
    private final static long serialVersionUID = 1;
	/**
	 * Constructor for VoidPropertySet.
	 * @param name the name associated with this property set.
	 */
	public VoidPropertySet(String name) {
		super(name, null);
	}

	/**
	 * @see PropertySet#getDataSize()
	 */
	@Override
    public int getDataSize() {
		return 4;
	}

	/**
	 * Stores the existence of a property at the given index. 
	 * @param index the index at which to establish the existence of the
	 * property.
	 */
	public void put(long index) {
		PropertyPage page = getOrCreatePage(getPageID(index));
		int n = page.getSize();
		page.add(getPageOffset(index));
		numProperties += page.getSize() - n;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.prop.PropertySet#moveIndex(long, long)
	 */
	@Override
    protected void moveIndex(long from, long to) {
		boolean value = hasProperty(from);
		remove(from);
		if (value) {
			put(to);
		}
		else {
			remove(to);
		}
	}
	/**
	 * saves the property at the given index to the given output stream.
	 */
	@Override
    protected void saveProperty(ObjectOutputStream oos, long index) throws IOException {
	}
	/**
	 * restores the property from the input stream to the given index.
	 */
	@Override
    protected void restoreProperty(ObjectInputStream ois, long index) throws IOException,
		ClassNotFoundException {
		this.put(index);
	}
	/**
	 * 
	 * @see ghidra.util.prop.PropertySet#applyValue(PropertyVisitor, long)
	 */
	@Override
    public void applyValue(PropertyVisitor visitor, long addr) {
		if (hasProperty(addr)) {
			visitor.visit();
		}
	}

}
