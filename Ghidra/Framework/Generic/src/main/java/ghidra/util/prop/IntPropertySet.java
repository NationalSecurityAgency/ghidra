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

import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

import java.io.*;

/**
 *  Handles  general storage and retrieval of int values indexed by long keys.
 * 
 */
public class IntPropertySet extends PropertySet {
    private final static long serialVersionUID = 1;
    
	/**
	 * Constructor for IntPropertySet.
	 * @param name the name associated with this property set
	 */
	public IntPropertySet(String name) {
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
	 * Stores an int value at the given index.  Any value currently at that
	 * index will be replaced by the new value.
	 * @param index the index at which to store the int value.
	 * @param value the int value to store.
	 */
	public void putInt(long index, int value) {
		PropertyPage page = getOrCreatePage(getPageID(index));
		int n = page.getSize();
		page.addInt(getPageOffset(index), value);
		numProperties += page.getSize() - n;
	}

	/**
	 * Retrieves the int value stored at the given index.
	 * @param index the index at which to retrieve the int value.
	 * @return int the value stored at the given index.
	 * @throws NoValueException if there is no int value stored at the index.
	 */
	public int getInt(long index) throws NoValueException {
		PropertyPage page = getPage(getPageID(index));
		if (page != null) {
			return page.getInt(getPageOffset(index));
		}
		throw noValueException;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.prop.PropertySet#moveIndex(long, long)
	 */
	@Override
    protected void moveIndex(long from, long to) {
		try {
			int value = getInt(from);
			remove(from);
			putInt(to, value);
		}catch(NoValueException e) {}
	}

	/**
	 * saves the property at the given index to the given output stream.
	 */
	@Override
    protected void saveProperty(ObjectOutputStream oos, long index) throws IOException {
		try {
			oos.writeInt(getInt(index));
		}
        catch(NoValueException e) {
            throw new AssertException(e.getMessage());
        }
	}
	/**
	 * restores the property from the input stream to the given index.
	 */
	@Override
    protected void restoreProperty(ObjectInputStream ois, long index) throws IOException{
		putInt(index, ois.readInt());
	}

	/**
	 * 
	 * @see ghidra.util.prop.PropertySet#applyValue(PropertyVisitor, long)
	 */
	@Override
    public void applyValue(PropertyVisitor visitor, long addr) {
		try {
			visitor.visit(getInt(addr));
		}
		catch(NoValueException e) {
		}
	}

}
