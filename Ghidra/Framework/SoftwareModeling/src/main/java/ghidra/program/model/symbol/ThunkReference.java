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
 * Implementation for a Thunk Function reference.
 * These references are dynamic in nature and may not be explicitly added,
 * removed or altered.  There presence is inferred by the existence
 * of a thunk function.
 * 
 */
public class ThunkReference implements DynamicReference {

	private static final int OPINDEX = OTHER;

	private Address fromAddr;
	private Address toAddr;

	/**
	 * Thunk reference constructor
	 * @param thunkAddr thunk function address
	 * @param thunkedAddr "thunked" function address
	 */
	public ThunkReference(Address thunkAddr, Address thunkedAddr) {
		this.fromAddr = thunkAddr;
		this.toAddr = thunkedAddr;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getFromAddress()
	 */
	@Override
	public Address getFromAddress() {
		return fromAddr;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getToAddress()
	 */
	@Override
	public Address getToAddress() {
		return toAddr;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getSymbolID()
	 */
	@Override
	public long getSymbolID() {
		return -1;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getReferenceType()
	 */
	@Override
	public RefType getReferenceType() {
		return RefType.THUNK;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#getOperandIndex()
	 */
	@Override
	public int getOperandIndex() {
		return OPINDEX;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isMnemonicReference()
	 */
	@Override
	public boolean isMnemonicReference() {
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isOperandReference()
	 */
	@Override
	public boolean isOperandReference() {
		return false;
	}

	/**
	 * @see java.lang.Comparable#compareTo(Object)
	 */
	@Override
	public int compareTo(Reference ref) {
		int result = fromAddr.compareTo(ref.getFromAddress());
		if (result == 0) {
			result = OPINDEX - ref.getOperandIndex();
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
		Reference ref = (Reference) obj;
		return ref.getReferenceType() == RefType.THUNK && fromAddr.equals(ref.getFromAddress()) &&
			toAddr.equals(ref.getToAddress());
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isExternalReference()
	 */
	@Override
	public boolean isExternalReference() {
		return false;
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
	 * @see ghidra.program.model.symbol.Reference#isMemoryReference()
	 */
	@Override
	public boolean isMemoryReference() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Reference#isRegisterReference()
	 */
	@Override
	public boolean isRegisterReference() {
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
		return SourceType.DEFAULT;
	}

}
