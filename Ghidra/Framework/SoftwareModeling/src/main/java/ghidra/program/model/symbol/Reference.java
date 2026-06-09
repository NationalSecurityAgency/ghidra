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
package ghidra.program.model.symbol;

import ghidra.program.model.address.Address;

/**
 * Base class to hold information about a referring address. Derived classes add
 * what the address is referring to. A basic reference consists of a "from"
 * address, the reference type, the operand index for where the reference is,
 * and whether the reference is user defined.
 */
public interface Reference extends Comparable<Reference> {

	/**
	 * Operand index which corresponds to the instruction/data mnemonic.
	 */
	public static final int MNEMONIC = -1;

	/**
	 * Special purpose operand index when not applicable (i.e., Thunk reference)
	 */
	public static final int OTHER = -2;

	/**
	 * {@return Get the address of the code unit that is making the reference.}
	 */
	public Address getFromAddress();

	/**
	 * {@return Get the "to" address for this reference.}
	 */
	public Address getToAddress();

	/**
	 * {@return Return whether this reference is marked as primary.}
	 */
	public boolean isPrimary();

	/**
	 * Get the symbol ID associated with this reference.
	 * Applies to memory references only.
	 * 
	 * @return symbol ID or -1 if no symbol is associated with this reference
	 */
	public long getSymbolID();

	/**
	 * {@return Get the type of reference being made.}
	 */
	public RefType getReferenceType();

	/**
	 * Get the operand index of where this reference was placed.
	 * 
	 * @return op index or ReferenceManager.MNEMONIC
	 */
	public int getOperandIndex();

	/**
	 * {@return Return true if this reference is on the Mnemonic and not on an operand.}
	 */
	public boolean isMnemonicReference();

	/**
	 * {@return Return true if this reference is on an operand and not on the Mnemonic.}
	 */
	public boolean isOperandReference();

	/**
	 * {@return Returns true if this reference is an instance of StackReference and
	 * refers to a stack location.}
	 */
	public boolean isStackReference();

	/**
	 * {@return Returns true if this reference is an instance of ExternalReference.}
	 */
	public boolean isExternalReference();

	/**
	 * {@return Returns true if this reference is an instance of EntryReference.}
	 */
	public boolean isEntryPointReference();

	/**
	 * {@return Returns true if this reference to an address in the programs memory
	 * space. This includes offset and shifted references.}
	 */
	public boolean isMemoryReference();

	/**
	 * {@return Returns true if this reference to an address in the programs register
	 * space.}
	 */
	public boolean isRegisterReference();

	/**
	 * {@return Returns true if this reference is an instance of OffsetReference.}
	 */
	public boolean isOffsetReference();

	/**
	 * {@return Returns true if this reference is an instance of ShiftedReference.}
	 */
	public boolean isShiftedReference();

	/**
	 * Gets the source of this reference. {@link SourceType}s
	 * 
	 * @return the source of this reference
	 */
	public SourceType getSource();
}
