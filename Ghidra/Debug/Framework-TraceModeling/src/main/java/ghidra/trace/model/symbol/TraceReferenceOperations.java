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

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Lifespan;

public interface TraceReferenceOperations {
	TraceReference addReference(TraceReference reference);

	TraceReference addReference(Lifespan lifespan, Reference reference);

	TraceReference addMemoryReference(Lifespan lifespan, Address fromAddress, Address toAddress,
			RefType refType, SourceType source, int operandIndex);

	TraceOffsetReference addOffsetReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, boolean toAddrIsBase, long offset, RefType refType,
			SourceType source, int operandIndex);

	TraceShiftedReference addShiftedReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, int shift, RefType refType, SourceType source, int operandIndex);

	TraceReference addRegisterReference(Lifespan lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex);

	TraceReference addStackReference(Lifespan lifespan, Address fromAddress, int toStackOffset,
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
	Collection<? extends TraceReference> getReferencesFromRange(Lifespan span,
			AddressRange range);

	TraceReference getPrimaryReferenceFrom(long snap, Address fromAddress, int operandIndex);

	Collection<? extends TraceReference> getFlowReferencesFrom(long snap, Address fromAddress);

	void clearReferencesFrom(Lifespan span, AddressRange range);

	Collection<? extends TraceReference> getReferencesTo(long snap, Address toAddress);

	void clearReferencesTo(Lifespan span, AddressRange range);

	/**
	 * TODO: Document me
	 * 
	 * This returns all references to addresses within the given range, regardless of operand index.
	 * 
	 * @param span
	 * @param range
	 * @return
	 */
	Collection<? extends TraceReference> getReferencesToRange(Lifespan span, AddressRange range);

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

	AddressSetView getReferenceSources(Lifespan span);

	AddressSetView getReferenceDestinations(Lifespan span);

	int getReferenceCountFrom(long snap, Address fromAddress);

	int getReferenceCountTo(long snap, Address toAddress);
}
