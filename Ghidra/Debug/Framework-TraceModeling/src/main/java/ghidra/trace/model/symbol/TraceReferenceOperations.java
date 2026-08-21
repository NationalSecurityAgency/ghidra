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
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

/**
 * The operations for adding and retrieving references
 */
public interface TraceReferenceOperations {
	/**
	 * A (a copy of) the given reference to this manager
	 * 
	 * @param reference the reference to add
	 * @return the resulting reference
	 */
	TraceReference addReference(TraceReference reference);

	/**
	 * A (a copy of) the given reference to this manager
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param reference the reference
	 * @return the resulting reference
	 */
	TraceReference addReference(Lifespan lifespan, Reference reference);

	/**
	 * Add a memory reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toRange the to addresses of the reference
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	TraceReference addMemoryReference(Lifespan lifespan, Address fromAddress, AddressRange toRange,
			RefType refType, SourceType source, int operandIndex);

	/**
	 * Add a memory reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toAddress the to address of the reference
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	default TraceReference addMemoryReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, RefType refType, SourceType source, int operandIndex) {
		return addMemoryReference(lifespan, fromAddress, new AddressRangeImpl(toAddress, toAddress),
			refType, source, operandIndex);
	}

	/**
	 * Add an offset memory reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toAddress the to address of the reference
	 * @param toAddrIsBase indicate whether or not toAddress incorporates the offset. False means
	 *            toAddress=base+offset. True means toAddress=base.
	 * @param offset value added to the base address
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	TraceOffsetReference addOffsetReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, boolean toAddrIsBase, long offset, RefType refType,
			SourceType source, int operandIndex);

	/**
	 * Add a shifted memory reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toAddress the to address of the reference
	 * @param shift the number of bits to shift left
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	TraceShiftedReference addShiftedReference(Lifespan lifespan, Address fromAddress,
			Address toAddress, int shift, RefType refType, SourceType source, int operandIndex);

	/**
	 * Add a register reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toRegister the to register of the reference
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	TraceReference addRegisterReference(Lifespan lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex);

	/**
	 * Add a (static) stack reference
	 * 
	 * @param lifespan the span of time where this reference applies
	 * @param fromAddress the from address of the reference
	 * @param toStackOffset the to offset of the reference
	 * @param refType the type of reference
	 * @param source how this reference was derived
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the resulting reference
	 */
	TraceReference addStackReference(Lifespan lifespan, Address fromAddress, int toStackOffset,
			RefType refType, SourceType source, int operandIndex);

	/**
	 * Find the reference that matches the given parameters
	 * 
	 * <p>
	 * <b>NOTE:</b> It is not sufficient to <em>intersect</em> the to range. It must exactly match
	 * that given.
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @param toRange the to address range
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the found reference or null
	 */
	TraceReference getReference(long snap, Address fromAddress, AddressRange toRange,
			int operandIndex);

	/**
	 * Find the reference that matches the given parameters
	 * 
	 * <p>
	 * <b>NOTE:</b> It is not sufficient to <em>contain</em> the to address. To to range must be a
	 * singleton and exactly match that given. To match a range, see
	 * {@link #getReference(long, Address, AddressRange, int)}
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @param toAddress the to address
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the found reference or null
	 */
	default TraceReference getReference(long snap, Address fromAddress, Address toAddress,
			int operandIndex) {
		return getReference(snap, fromAddress, new AddressRangeImpl(toAddress, toAddress),
			operandIndex);
	}

	/**
	 * Find all references from the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getReferencesFrom(long snap, Address fromAddress);

	/**
	 * Find all references from the given snapshot, address, and operand index
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getReferencesFrom(long snap, Address fromAddress,
			int operandIndex);

	/**
	 * Find all references with from addresses contained in the given lifespan and address range
	 * 
	 * @param span the lifespan to examine
	 * @param range the range to examine
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getReferencesFromRange(Lifespan span,
			AddressRange range);

	/**
	 * Get the primary reference matching from the given snapshot, address, and operand index
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @param operandIndex the operand index for the "from" end, or -1
	 * @return the found reference or null
	 */
	TraceReference getPrimaryReferenceFrom(long snap, Address fromAddress, int operandIndex);

	/**
	 * Get all flow references from the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getFlowReferencesFrom(long snap, Address fromAddress);

	/**
	 * Clear all references from the given lifespan and address range
	 * 
	 * <p>
	 * Any reference intersecting the given "from" parameters will have its lifespan truncated to
	 * the start of the given lifespan.
	 * 
	 * @param span the lifespan to remove
	 * @param range the range to clear
	 */
	void clearReferencesFrom(Lifespan span, AddressRange range);

	/**
	 * Get all references whose to address (or range) contains the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param toAddress the to address
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getReferencesTo(long snap, Address toAddress);

	/**
	 * Clear all references to the given lifespan and address range
	 * 
	 * <p>
	 * Any reference intersecting the given "to" parameters will have its lifespan truncated to the
	 * start of the given lifespan.
	 * 
	 * @param span the lifespan to remove
	 * @param range the range of clear
	 */
	void clearReferencesTo(Lifespan span, AddressRange range);

	/**
	 * Get all references whose to address range intersects the given lifespan and address range
	 * 
	 * <p>
	 * The following iteration orders may be specified for the resulting (lazy) collection:
	 * 
	 * <ul>
	 * <li>{@code null} - no particular order. This spares the cost of sorting.</li>
	 * <li>{@link Rectangle2DDirection#TOPMOST} - most-recent (latest snapshot) first.</li>
	 * <li>{@link Rectangle2DDirection#BOTTOMMOST} - least-recent (earliest including scratch
	 * snapshot first).</li>
	 * <li>{@link Rectangle2DDirection#LEFTMOST} - smallest address first.</li>
	 * <li>{@link Rectangle2DDirection#RIGHTMOST} - largest address first.</li>
	 * </ul>
	 * 
	 * <p>
	 * "Secondary" sorting is not supported.
	 * 
	 * @param span the lifespan to examine
	 * @param range the range to examine
	 * @param order the order of items in the collection.
	 * @return the collection of results
	 */
	Collection<? extends TraceReference> getReferencesToRange(Lifespan span, AddressRange range,
			Rectangle2DDirection order);

	/**
	 * Get all references whose to address range intersects the given lifespan and address range
	 * 
	 * @param span the lifespan to examine
	 * @param range the range to examine
	 * @return the collection of results
	 */
	default Collection<? extends TraceReference> getReferencesToRange(Lifespan span,
			AddressRange range) {
		return getReferencesToRange(span, range, null);
	}

	// NOTE: Variable references are not (yet?) supported

	/**
	 * Check if there exists a reference from the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @return true if one or more references exist
	 */
	default boolean hasReferencesFrom(long snap, Address fromAddress) {
		return !getReferencesFrom(snap, fromAddress).isEmpty();
	}

	/**
	 * Check if there exists a reference from the given snapshot, address, and operand
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @param operandIndex the operand index, or -1
	 * @return true if one or more references exist
	 */
	default boolean hasReferencesFrom(long snap, Address fromAddress, int operandIndex) {
		return !getReferencesFrom(snap, fromAddress, operandIndex).isEmpty();
	}

	/**
	 * Check if there exists a flow reference from the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @return true if one or more flow references exist
	 */
	default boolean hasFlowReferencesFrom(long snap, Address fromAddress) {
		return !getFlowReferencesFrom(snap, fromAddress).isEmpty();
	}

	/**
	 * Check if there exists a reference to the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param toAddress the to address
	 * @return true if one or more references exists
	 */
	default boolean hasReferencesTo(long snap, Address toAddress) {
		return !getReferencesTo(snap, toAddress).isEmpty();
	}

	/**
	 * Get an address set of all "from" addresses in any reference intersecting the given lifespan
	 * 
	 * @param span the lifespan to examine
	 * @return a (lazily-computed) address set view of all "from" addresses
	 */
	AddressSetView getReferenceSources(Lifespan span);

	/**
	 * Get an address set of all "to" addresses in any reference intersecting the given lifespan
	 * 
	 * @param span the lifespan to examine
	 * @return a (lazily-computed) address set view of all "to" addresses
	 */
	AddressSetView getReferenceDestinations(Lifespan span);

	/**
	 * Count the number of references from the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param fromAddress the from address
	 * @return the number of references
	 */
	int getReferenceCountFrom(long snap, Address fromAddress);

	/**
	 * Count the number of references to the given snapshot and address
	 * 
	 * @param snap the snapshot key
	 * @param toAddress the to address
	 * @return the number of references
	 */
	int getReferenceCountTo(long snap, Address toAddress);
}
