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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;

/**
 *
 * Implementation for a reference, not associated with a program. 
 */
public class MemReferenceImpl implements Reference {

	private Address fromAddr;
	private Address toAddr;
	protected RefType refType;
	protected int opIndex;
	protected SourceType sourceType;
	protected long symbolID;
	protected boolean isPrimary;
	
	/**
 	 * Constructs a MemReferenceImpl.
	 * @param fromAddr reference from address
	 * @param toAddr reference to address
	 * @param refType the type of the reference
	 * @param sourceType reference source type {@link SourceType}
	 * @param opIndex the operand index of the from location
	 * @param isPrimary true if this reference should substitue the operand
	 */
	public MemReferenceImpl(Address fromAddr, 
							Address toAddr, 
							RefType refType,
							SourceType sourceType, 
							int opIndex, 
							boolean isPrimary) {
		this.fromAddr = fromAddr;
		this.toAddr = toAddr;
		this.refType = refType;
		this.opIndex = opIndex;
		this.sourceType = sourceType;
		this.isPrimary = isPrimary;
		symbolID = -1;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getFromAddress()
	 */
	public Address getFromAddress() {
		return fromAddr;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getToAddress()
	 */
	public Address getToAddress() {
		return toAddr;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isPrimary()
	 */
	public boolean isPrimary() {
		return isPrimary;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getSymbolID()
	 */
	public long getSymbolID() {
		return symbolID;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getReferenceType()
	 */
	public RefType getReferenceType() {
		return refType;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getOperandIndex()
	 */
	public int getOperandIndex() {
		return opIndex;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isMnemonicReference()
	 */
	public boolean isMnemonicReference() {
		return !isOperandReference();
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isOperandReference()
	 */
	public boolean isOperandReference() {
		return opIndex >= 0;
	}

	/**
	 * @see java.lang.Comparable#compareTo(Object)
	 */
	public int compareTo(Reference ref) {
		int result = fromAddr.compareTo(ref.getFromAddress());
		if (result == 0) {
			result = opIndex - ref.getOperandIndex();
			if (result == 0) {
				return toAddr.compareTo(ref.getToAddress());
			}
		}
		return result;
	}
	
	/**
     * @see java.lang.Object#equals(Object)
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Reference)) {
            return false;
        }
        Reference ref = (Reference)obj;
        return isMemoryReference() &&
				fromAddr.equals(ref.getFromAddress()) &&
	            toAddr.equals(ref.getToAddress()) &&
	            opIndex == ref.getOperandIndex() &&
				symbolID == ref.getSymbolID() &&
				isPrimary == ref.isPrimary() &&
				sourceType == ref.getSource() &&
				refType == ref.getReferenceType() &&
				isShiftedReference() == ref.isShiftedReference() &&
				isOffsetReference() == ref.isOffsetReference();
    } 

	/**
	 * @see ghidra.program.model.symbol.Reference#isExternalReference()
	 */
	public boolean isExternalReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isOffsetReference()
	 */
	public boolean isOffsetReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isShiftedReference()
	 */
	public boolean isShiftedReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isEntryPointReference()
	 */
    public boolean isEntryPointReference() {
        return false;
    }

	/**
	 * @see ghidra.program.model.symbol.Reference#isMemoryReference()
	 */
	public boolean isMemoryReference() {
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isRegisterReference()
	 */
	public boolean isRegisterReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isStackReference()
	 */
	public boolean isStackReference() {
		return false;
	}

	public SourceType getSource() {
		return sourceType;
	}
	public void setSource(SourceType source) {
		this.sourceType = source;
	}

}
