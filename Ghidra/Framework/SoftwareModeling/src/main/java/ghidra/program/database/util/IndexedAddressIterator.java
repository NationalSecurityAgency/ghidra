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
package ghidra.program.database.util;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import db.DBFieldIterator;
import db.Field;
import db.util.ErrorHandler;

/**
 * Iterates over a FieldIterator; the field is the address but not
 * the key; the column for the field must be indexed.
 *
 * 
 */
public class IndexedAddressIterator implements AddressIterator {
	private DBFieldIterator iter;
	private AddressMap addrMap;
	private ErrorHandler errHandler;

	/**
	 * 
	 * Constructor
	 * @param iter field iterator that is the address
	 * @param addrMap address map to convert the longs to addresses
	 * @param colIndex indexed column in the record
	 */
	public IndexedAddressIterator(DBFieldIterator iter, AddressMap addrMap, int colIndex,
			ErrorHandler errHandler) {
		this.iter = iter;
		this.addrMap = addrMap;
		this.errHandler = errHandler;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.address.AddressIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		try {
			return iter.hasNext();
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.address.AddressIterator#next()
	 */
	@Override
	public Address next() {
		try {
			Field field = iter.next();
			if (field != null) {
				long addr = field.getLongValue();
				return addrMap.decodeAddress(addr);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		catch (NoSuchElementException e) {
		}
		return null;
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
