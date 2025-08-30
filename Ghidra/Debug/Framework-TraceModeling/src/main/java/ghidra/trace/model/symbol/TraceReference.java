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
package ghidra.trace.model.symbol;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;

/**
 * A {@link Reference} within a {@link Trace}
 */
public interface TraceReference extends Reference {
	/**
	 * Get the trace containing this reference
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the lifespan for which this reference is effective
	 * 
	 * @return the lifespan
	 */
	Lifespan getLifespan();

	/**
	 * Get the starting snapshot key of this reference's lifespan
	 * 
	 * @return the starting snapshot
	 * @see #getLifespan()
	 */
	long getStartSnap();

	/**
	 * Get the "to" range of this reference.
	 * 
	 * <p>
	 * Because references are often used in traces to indicate <em>actual</em> run-time writes, it
	 * is not sufficient to examine the code unit at a single "to" address and assume the reference
	 * is to the entire unit. For one, the read might be of a specific field in a structure data
	 * unit. For two, a read of a large unit may be implemented as a loop of several smaller reads.
	 * The trace could (and probably should) record each atomic read. In theory, one could examine
	 * the "from" instruction and operand index to derive the length, but that is onerous and not
	 * indexed. So instead, we record the exact "to" range in each reference and index it. This
	 * allows for easy implementation of, e.g., access breakpoints.
	 * 
	 * @return the to range
	 */
	AddressRange getToRange();

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * For a trace reference, the "to" part is actually a range. This returns the minimum address of
	 * that range.
	 * 
	 * @see #getToRange()
	 */
	@Override
	default Address getToAddress() {
		return getToRange().getMinAddress();
	}

	/**
	 * Make this reference primary.
	 * 
	 * Only one reference at a given "from" location can be primary. If a primary reference already
	 * exists at this location, it will become a secondary reference.
	 * 
	 * @param primary
	 */
	void setPrimary(boolean primary);

	/**
	 * Set the reference type
	 * 
	 * @param refType the new reference type
	 */
	void setReferenceType(RefType refType);

	/**
	 * Set the symbol associated with this reference
	 * 
	 * @param symbol the symbol
	 * @see #getSymbolID()
	 */
	void setAssociatedSymbol(Symbol symbol);

	/**
	 * Clear the associated symbol
	 * 
	 * @see #getSymbolID()
	 */
	void clearAssociatedSymbol();

	/**
	 * Get the symbol associated with this reference
	 * 
	 * @return the symbol
	 * @see #getSymbolID()
	 */
	default Symbol getAssociatedSymbol() {
		long id = getSymbolID();
		return id == -1 ? null : getTrace().getSymbolManager().getSymbolByID(id);
	}

	@Override
	default boolean isMnemonicReference() {
		return !isOperandReference();
	}

	@Override
	default boolean isOperandReference() {
		return getOperandIndex() >= 0;
	}

	@Override
	default boolean isStackReference() {
		return false; // TraceStackReference should override
	}

	@Override
	default boolean isExternalReference() {
		return false; // Trace should have all modules
	}

	@Override
	default boolean isEntryPointReference() {
		return false; // I'm not inclined to record entry point in Traces
	}

	@Override
	default boolean isMemoryReference() {
		return getToAddress().isMemoryAddress();
	}

	@Override
	default boolean isRegisterReference() {
		return getToAddress().isRegisterAddress();
	}

	@Override
	default boolean isOffsetReference() {
		return false; // TraceOffsetReference should override
	}

	@Override
	default boolean isShiftedReference() {
		return false; // TraceShiftedReference should override
	}

	@Override
	default int compareTo(Reference that) {
		int result;
		result = this.getFromAddress().compareTo(that.getFromAddress());
		if (result != 0) {
			return result;
		}
		result = Integer.compare(getOperandIndex(), that.getOperandIndex());
		if (result != 0) {
			return result;
		}
		result = this.getToAddress().compareTo(that.getToAddress());
		if (result != 0) {
			return result;
		}
		return 0;
	}

	/**
	 * Delete this reference
	 */
	void delete();
}
