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
package ghidra.program.database.code;

import ghidra.program.database.map.AddressMap;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

import java.io.IOException;

import db.DBLongIterator;

/** 
 * Converts a DBLongIterator into a DataIterator
 */
public class DataKeyIterator implements DataIterator {
	private CodeManager codeMgr;
	private DBLongIterator it;
	private Data nextCu;
	private AddressMap addrMap;

	/**
	 * Constructs a new DataKeyIterator
	 * @param codeMgr the code manager
	 * @param addrMap the address map to convert keys to addresses.
	 * @param it DBLongIterator
	 */
	public DataKeyIterator(CodeManager codeMgr, AddressMap addrMap, DBLongIterator it) {
		this.codeMgr = codeMgr;
		this.addrMap = addrMap;
		this.it = it;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	public boolean hasNext() {
		if (nextCu == null) {
			findNext();
		}
		return nextCu != null;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	public Data next() {
		if (hasNext()) {
			Data ret = nextCu;
			nextCu = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		try {
			while (nextCu == null && it.hasNext()) {
				long addr = it.next();
				nextCu = codeMgr.getDataAt(addrMap.decodeAddress(addr), addr);
			}
		}
		catch (IOException e) {
		}
	}

}
