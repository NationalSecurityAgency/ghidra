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

import com.google.common.collect.Range;

import ghidra.program.model.symbol.*;
import ghidra.trace.model.Trace;

public interface TraceReference extends Reference {
	Trace getTrace();

	Range<Long> getLifespan();

	long getStartSnap();

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

	void setAssociatedSymbol(Symbol symbol);

	void clearAssociatedSymbol();

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

	void delete();
}
