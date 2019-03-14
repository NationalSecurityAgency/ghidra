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
package ghidra.program.database.references;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

abstract class ReferenceDB implements Reference {

	protected Address fromAddr;
	protected Address toAddr;
	protected RefType refType;
	protected int opIndex;
	protected SourceType sourceType;
	protected long symbolID;
	protected boolean isPrimary;

	ReferenceDB(Address fromAddr, Address toAddr, RefType refType, int opIndex,
			SourceType sourceType, boolean isPrimary, long symbolID) {
		this.fromAddr = fromAddr;
		this.toAddr = toAddr;
		this.refType = refType;
		this.opIndex = opIndex;
		this.sourceType = sourceType;
		this.isPrimary = isPrimary;
		this.symbolID = symbolID;
	}

	/**
	 * @see java.lang.Object#equals(Object)
	 */
	@Override
	public abstract boolean equals(Object obj);

	/**
	 * Get the address of the codeunit that is making the reference.
	 */
	@Override
	public Address getFromAddress() {
		return fromAddr;
	}

	/**
	 * Get the type of reference being made.
	 */
	@Override
	public RefType getReferenceType() {
		return refType;
	}

	/**
	 * Get the operand index of where this reference was placed.
	 * 
	 * @return op index or ReferenceManager.MNEMONIC
	 */
	@Override
	public int getOperandIndex() {
		return opIndex;
	}

	/**
	 * Return true if this reference is on the mnemonic (versus an operand)
	 */
	@Override
	public boolean isMnemonicReference() {
		return !isOperandReference();
	}

	/**
	 * Return true if this reference is on an operand.
	 */
	@Override
	public boolean isOperandReference() {
		return opIndex >= 0;
	}

	/**
	 * @see java.lang.Object#hashCode
	 */
	@Override
	public int hashCode() {
		return fromAddr.hashCode();
	}

	/**
	 * Return a string that represents this references, for debugging purposes.
	 */
	@Override
	public String toString() {
		return "From: " + fromAddr + " To: " + toAddr + " Type: " + refType + " Op: " + opIndex +
			" " + sourceType.toString();
	}

	/**
	 * @see java.lang.Comparable#compareTo(Object)
	 */
	@Override
	public final int compareTo(Reference r) {
		int result = fromAddr.compareTo(r.getFromAddress());
		if (result == 0) {
			result = opIndex - r.getOperandIndex();
			if (result == 0) {
				return toAddr.compareTo(r.getToAddress());
			}
		}
		return result;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getSymbolID()
	 */
	@Override
	public long getSymbolID() {
		return symbolID;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getToAddress()
	 */
	@Override
	public Address getToAddress() {
		return toAddr;
	}

	@Override
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isExternalReference()
	 */
	@Override
	public boolean isExternalReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isMemoryReference()
	 */
	@Override
	public boolean isMemoryReference() {
		return toAddr.isMemoryAddress();
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isRegisterReference()
	 */
	@Override
	public boolean isRegisterReference() {
		return toAddr.isRegisterAddress();
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isOffsetReference()
	 */
	@Override
	public boolean isOffsetReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isShiftedReference()
	 */
	@Override
	public boolean isShiftedReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isEntryPointReference()
	 */
	@Override
	public boolean isEntryPointReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isStackReference()
	 */
	@Override
	public boolean isStackReference() {
		return false;
	}

	@Override
	public SourceType getSource() {
		return sourceType;
	}

}
