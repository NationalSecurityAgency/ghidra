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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.util.Iterator;

/**
 * Combines an Instruction iterator and Data iterator into a codeunit iterator
 */

class CodeUnitRecordIterator implements CodeUnitIterator {
	private CodeManager codeMgr;
	private InstructionIterator instIt;
	private DataIterator dataIt;
	private AddressIterator addrIt;
	private boolean forward;

	private Address nextAddr;
	private Instruction nextInst;
	private Data nextData;
	private CodeUnit nextCu;

	/**
	 * Constructs a new CodeUnitRecordIterator
	 * @param codeMgr the code managaer
	 * @param instIt the instruction iterator
	 * @param dataIt the data iterator
	 * @param set the address set
	 * @param forward the iterator direction
	 */
	CodeUnitRecordIterator(CodeManager codeMgr, InstructionIterator instIt, DataIterator dataIt,
			AddressSetView set, boolean forward) {
		this.codeMgr = codeMgr;
		this.instIt = instIt;
		this.dataIt = dataIt;
		this.forward = forward;
		addrIt = set.getAddresses(forward);
		nextAddr = addrIt.next();
		nextData = dataIt.next();
		nextInst = instIt.next();

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
		while (nextAddr != null && nextCu == null) {
			CodeUnit nextDefined = null;

			if (nextInst == null) {
				nextDefined = nextData;
			}
			else if (nextData == null) {
				nextDefined = nextInst;
			}
			else {
				int c = nextInst.getMinAddress().compareTo(nextData.getMinAddress());
				c = forward ? c : -c;
				nextDefined = (c < 0) ? (CodeUnit) nextInst : (CodeUnit) nextData;
			}
			if (nextDefined != null && !nextDefined.contains(nextAddr)) {
				nextDefined = null;
			}
			if (nextDefined != null) {
				if (nextDefined == nextInst) {
					nextInst = instIt.next();
				}
				else {
					nextData = dataIt.next();
				}
			}
			else {
				nextDefined = codeMgr.getUndefinedAt(nextAddr);
			}
			nextAddr = getNextAddr(nextAddr, nextDefined);
			nextCu = nextDefined;
		}
	}

	private Address getNextAddr(Address addr, CodeUnit cu) {
		if (cu == null) {
			return addrIt.next();
		}
		if (forward) {
			Address end = cu.getMaxAddress();
			while (addr != null && addr.compareTo(end) <= 0) {
				addr = addrIt.next();
			}
		}
		else {
			Address start = cu.getMinAddress();
			while (addr != null && addr.compareTo(start) >= 0) {
				addr = addrIt.next();
			}
		}
		return addr;
	}

	@Override
	public Iterator<CodeUnit> iterator() {
		return this;
	}

}
