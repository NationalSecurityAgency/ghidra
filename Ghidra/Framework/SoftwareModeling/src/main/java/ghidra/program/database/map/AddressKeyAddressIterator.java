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
package ghidra.program.database.map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;

import java.io.IOException;
import java.util.Iterator;
import java.util.NoSuchElementException;

import db.DBLongIterator;
import db.util.ErrorHandler;

/**
 * Converts an AddressKeyIterator or an addressKeyAddressIterator into an AddressIterator
 */
public class AddressKeyAddressIterator implements AddressIterator {

	private DBLongIterator keyIter;
	private AddressMap addrMap;
	private ErrorHandler errHandler;
	private boolean forward;

	/**
	 * Constructor.
	 * @param keyIter address key iterator, may be null.  All long values must decode properly with the specified addrMap.
	 * @param addrMap address map
	 * @param errHandler IO error handler (may be null)
	 */
	public AddressKeyAddressIterator(DBLongIterator keyIter, boolean forward, AddressMap addrMap,
			ErrorHandler errHandler) {
		this.keyIter = keyIter;
		this.addrMap = addrMap;
		this.forward = forward;
		this.errHandler = errHandler;
	}

	/**
	 * @see ghidra.program.model.address.AddressIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		try {
			return keyIter != null && (forward ? keyIter.hasNext() : keyIter.hasPrevious());
		}
		catch (IOException e) {
			if (errHandler != null) {
				errHandler.dbError(e);
			}
		}
		return false;
	}

	/**
	 * @see ghidra.program.model.address.AddressIterator#next()
	 */
	@Override
	public Address next() {
		if (keyIter == null) {
			return null;
		}
		Address addr = null;
		try {
			addr = addrMap.decodeAddress(forward ? keyIter.next() : keyIter.previous());
		}
		catch (NoSuchElementException e) {
			return null;
		}
		catch (IOException e) {
			if (errHandler != null) {
				errHandler.dbError(e);
			}
		}
		return addr;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
