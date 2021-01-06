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

import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;

public interface TraceReferenceOperations {
	TraceReference addReference(TraceReference reference);

	TraceReference addReference(Range<Long> lifespan, Reference reference);

	TraceReference addMemoryReference(Range<Long> lifespan, Address fromAddress, Address toAddress,
			RefType refType, SourceType source, int operandIndex);

	TraceOffsetReference addOffsetReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, long offset, RefType refType, SourceType source, int operandIndex);

	TraceShiftedReference addShiftedReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, int shift, RefType refType, SourceType source, int operandIndex);

	TraceReference addRegisterReference(Range<Long> lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex);

	TraceReference addStackReference(Range<Long> lifespan, Address fromAddress, int toStackOffset,
			RefType refType, SourceType source, int operandIndex);

	TraceReference getReference(long snap, Address fromAddress, Address toAddress,
			int operandIndex);

	Collection<? extends TraceReference> getReferencesFrom(long snap, Address fromAddress);

	Collection<? extends TraceReference> getReferencesFrom(long snap, Address fromAddress,
			int operandIndex);

	/**
	 * TODO: Document me
	 * 
	 * This returns all references from addresses within the given range, regardless of operand
	 * index.
	 * 
	 * @param span
	 * @param range
	 * @return
	 */
	Collection<? extends TraceReference> getReferencesFromRange(Range<Long> span,
			AddressRange range);

	TraceReference getPrimaryReferenceFrom(long snap, Address fromAddress, int operandIndex);

	Collection<? extends TraceReference> getFlowReferencesFrom(long snap, Address fromAddress);

	void clearReferencesFrom(Range<Long> span, AddressRange range);

	Collection<? extends TraceReference> getReferencesTo(long snap, Address toAddress);

	/**
	 * TODO: Document me
	 * 
	 * This returns all references to addresses within the given range, regardless of operand index.
	 * 
	 * @param span
	 * @param range
	 * @return
	 */
	Collection<? extends TraceReference> getReferencesToRange(Range<Long> span, AddressRange range);

	// TODO: Support Variable references

	default boolean hasReferencesFrom(long snap, Address fromAddress) {
		return !getReferencesFrom(snap, fromAddress).isEmpty();
	}

	default boolean hasReferencesFrom(long snap, Address fromAddress, int operandIndex) {
		return !getReferencesFrom(snap, fromAddress, operandIndex).isEmpty();
	}

	default boolean hasFlowReferencesFrom(long snap, Address fromAddress) {
		return !getFlowReferencesFrom(snap, fromAddress).isEmpty();
	}

	default boolean hasReferencesTo(long snap, Address toAddress) {
		return !getReferencesTo(snap, toAddress).isEmpty();
	}

	AddressSetView getReferenceSources(Range<Long> span);

	AddressSetView getReferenceDestinations(Range<Long> span);

	int getReferenceCountFrom(long snap, Address fromAddress);

	int getReferenceCountTo(long snap, Address toAddress);
}
