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

import ghidra.program.database.map.AddressKeyIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;

import java.io.IOException;
import java.util.Iterator;

/**
 * Converts an AddressKeyIterator into a CodeUnitIterator
 */

public class CodeUnitKeyIterator implements CodeUnitIterator {
	private CodeManager codeMgr;
	private AddressKeyIterator it;
	private boolean forward;
	private CodeUnit nextCu;

	/**
	 * Construct a new CodeUnitKeyIterator
	 * @param codeMgr the code manager
	 * @param it the addressKeyIterator
	 * @param forward the direction to iterate.
	 */
	public CodeUnitKeyIterator(CodeManager codeMgr, AddressKeyIterator it, boolean forward) {
		this.codeMgr = codeMgr;
		this.it = it;
		this.forward = forward;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		if (nextCu == null) {
			findNext();
		}
		return nextCu != null;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	@Override
	public CodeUnit next() {
		if (hasNext()) {
			CodeUnit ret = nextCu;
			nextCu = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		try {
			while (nextCu == null) {
				long addr;
				if (forward) {
					if (!it.hasNext()) {
						break;
					}
					addr = it.next();
				}
				else {
					if (!it.hasPrevious()) {
						break;
					}
					addr = it.previous();
				}
				nextCu = codeMgr.getCodeUnitAt(addr);
			}
		}
		catch (IOException e) {
		}
	}

	@Override
	public Iterator<CodeUnit> iterator() {
		return this;
	}

}
