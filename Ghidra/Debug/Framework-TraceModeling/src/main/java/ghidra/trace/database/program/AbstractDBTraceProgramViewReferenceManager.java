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
package ghidra.trace.database.program;

import static ghidra.lifecycle.Unfinished.TODO;

import java.util.Collection;
import java.util.Collections;

import javax.help.UnsupportedOperationException;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.symbol.DBTraceReferenceManager;
import ghidra.trace.model.listing.TraceCodeOperations;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceReferenceOperations;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public abstract class AbstractDBTraceProgramViewReferenceManager implements ReferenceManager {
	protected final DBTraceProgramView program;
	protected TraceReferenceOperations refs;
	protected TraceCodeOperations code;

	protected final DBTraceReferenceManager refsManager;

	public AbstractDBTraceProgramViewReferenceManager(DBTraceProgramView program) {
		this.program = program;
		this.refs = getReferenceOperations(false);
		this.code = getCodeOperations(false);

		this.refsManager = program.trace.getReferenceManager();
	}

	protected abstract TraceReferenceOperations getReferenceOperations(boolean createIfAbsent);

	protected abstract TraceCodeOperations getCodeOperations(boolean createIfAbsent);

	private TraceReferenceOperations refs(boolean createIfAbsent) {
		if (refs == null) {
			refs = getReferenceOperations(createIfAbsent);
		}
		return refs;
	}

	private TraceCodeOperations code(boolean createIfAbsent) {
		if (code == null) {
			code = getCodeOperations(createIfAbsent);
		}
		return code;
	}

	protected Range<Long> chooseLifespan(Address fromAddr) {
		TraceCodeUnit unit = code(false) == null
				? null
				: code.codeUnits().getAt(program.snap, fromAddr);
		return unit == null ? Range.atLeast(program.snap) : unit.getLifespan();
	}

	@Override
	public Reference addReference(Reference reference) {
		return refs(true).addReference(chooseLifespan(reference.getFromAddress()), reference);
	}

	@Override
	public Reference addStackReference(Address fromAddr, int opIndex, int stackOffset, RefType type,
			SourceType source) {
		return refs(true).addStackReference(chooseLifespan(fromAddr), fromAddr, stackOffset, type,
			source, opIndex);
	}

	@Override
	public Reference addRegisterReference(Address fromAddr, int opIndex, Register register,
			RefType type, SourceType source) {
		return refs(true).addRegisterReference(chooseLifespan(fromAddr), fromAddr, register, type,
			source, opIndex);
	}

	@Override
	public Reference addMemoryReference(Address fromAddr, Address toAddr, RefType type,
			SourceType source, int opIndex) {
		return refs(true).addMemoryReference(chooseLifespan(fromAddr), fromAddr, toAddr, type,
			source,
			opIndex);
	}

	@Override
	public Reference addOffsetMemReference(Address fromAddr, Address toAddr, long offset,
			RefType type, SourceType source, int opIndex) {
		return refs(true).addOffsetReference(chooseLifespan(fromAddr), fromAddr, toAddr, offset,
			type,
			source, opIndex);
	}

	@Override
	public Reference addShiftedMemReference(Address fromAddr, Address toAddr, int shiftValue,
			RefType type, SourceType source, int opIndex) {
		return refs(true).addShiftedReference(chooseLifespan(fromAddr), fromAddr, toAddr,
			shiftValue,
			type, source, opIndex);
	}

	@Override
	public Reference addExternalReference(Address fromAddr, String libraryName, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addExternalReference(Address fromAddr, Namespace extNamespace, String extLabel,
			Address extAddr, SourceType source, int opIndex, RefType type)
			throws InvalidInputException, DuplicateNameException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Reference addExternalReference(Address fromAddr, int opIndex, ExternalLocation location,
			SourceType source, RefType type) throws InvalidInputException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAllReferencesFrom(Address beginAddr, Address endAddr) {
		if (refs(false) == null) {
			return;
		}
		refs.clearReferencesFrom(Range.closed(program.snap, program.snap),
			new AddressRangeImpl(beginAddr, endAddr));
	}

	@Override
	public void removeAllReferencesFrom(Address fromAddr) {
		if (refs(false) == null) {
			return;
		}
		refs.clearReferencesFrom(Range.closed(program.snap, program.snap),
			new AddressRangeImpl(fromAddr, fromAddr));
	}

	@Override
	public Reference[] getReferencesTo(Variable var) {
		return TODO();
	}

	@Override
	public Variable getReferencedVariable(Reference reference) {
		return TODO();
	}

	@Override
	public void setPrimary(Reference ref, boolean isPrimary) {
		DBTraceReference dbRef = refsManager.assertIsMine(ref);
		dbRef.setPrimary(isPrimary);
	}

	@Override
	public boolean hasFlowReferencesFrom(Address addr) {
		if (refs(false) == null) {
			return false;
		}
		return !refs.getFlowRefrencesFrom(program.snap, addr).isEmpty();
	}

	@Override
	public Reference[] getFlowReferencesFrom(Address addr) {
		Collection<? extends TraceReference> from = refs(false) == null
				? Collections.emptyList()
				: refs.getFlowRefrencesFrom(program.snap, addr);
		// TODO: Requires two traversals. Not terrible for this size....
		return from.toArray(new Reference[from.size()]);
	}

	@Override
	public ReferenceIterator getExternalReferences() {
		return new ReferenceIteratorAdapter(Collections.emptyIterator());
	}

	@Override
	public ReferenceIterator getReferencesTo(Address addr) {
		Collection<? extends TraceReference> to = refs(false) == null
				? Collections.emptyList()
				: refs.getReferencesTo(program.snap, addr);
		return new ReferenceIteratorAdapter(to.iterator());
	}

	@Override
	public ReferenceIterator getReferenceIterator(Address startAddr) {
		Collection<? extends TraceReference> from = refs(false) == null
				? Collections.emptyList()
				: refs.getReferencesFrom(program.snap, startAddr);
		return new ReferenceIteratorAdapter(from.iterator());
	}

	@Override
	public Reference getReference(Address fromAddr, Address toAddr, int opIndex) {
		return refs(false) == null
				? null
				: refs.getReference(program.snap, fromAddr, toAddr, opIndex);
	}

	@Override
	public Reference[] getReferencesFrom(Address addr) {
		Collection<? extends TraceReference> from = refs(false) == null
				? Collections.emptyList()
				: refs.getReferencesFrom(program.snap, addr);
		return from.toArray(new Reference[from.size()]);
	}

	@Override
	public Reference[] getReferencesFrom(Address fromAddr, int opIndex) {
		Collection<? extends TraceReference> from = refs(false) == null
				? Collections.emptyList()
				: refs.getReferencesFrom(program.snap, fromAddr, opIndex);
		return from.toArray(new Reference[from.size()]);
	}

	@Override
	public boolean hasReferencesFrom(Address fromAddr, int opIndex) {
		return refs(false) == null
				? false
				: !refs.getReferencesFrom(program.snap, fromAddr, opIndex).isEmpty();
	}

	@Override
	public boolean hasReferencesFrom(Address fromAddr) {
		return refs(false) == null
				? false
				: !refs.getReferencesFrom(program.snap, fromAddr).isEmpty();
	}

	@Override
	public Reference getPrimaryReferenceFrom(Address addr, int opIndex) {
		return refs(false) == null
				? null
				: refs.getPrimaryReferenceFrom(program.snap, addr, opIndex);
	}

	@Override
	public AddressIterator getReferenceSourceIterator(Address startAddr, boolean forward) {
		return refs(false) == null
				? new EmptyAddressIterator()
				: refs.getReferenceSources(Range.closed(program.snap, program.snap))
						.getAddresses(startAddr, forward);
	}

	@Override
	public AddressIterator getReferenceSourceIterator(AddressSetView addrSet, boolean forward) {
		return refs(false) == null
				? new EmptyAddressIterator()
				: new IntersectionAddressSetView(
					refs.getReferenceSources(Range.closed(program.snap, program.snap)), addrSet)
							.getAddresses(forward);
	}

	@Override
	public AddressIterator getReferenceDestinationIterator(Address startAddr, boolean forward) {
		return refs(false) == null
				? new EmptyAddressIterator()
				: refs.getReferenceDestinations(Range.closed(program.snap, program.snap))
						.getAddresses(startAddr, forward);
	}

	@Override
	public AddressIterator getReferenceDestinationIterator(AddressSetView addrSet,
			boolean forward) {
		return refs(false) == null
				? new EmptyAddressIterator()
				: new IntersectionAddressSetView(
					refs.getReferenceDestinations(Range.closed(program.snap, program.snap)),
					addrSet).getAddresses(forward);
	}

	@Override
	public int getReferenceCountTo(Address toAddr) {
		return refs(false) == null
				? 0
				: refs.getReferenceCountTo(program.snap, toAddr);
	}

	@Override
	public int getReferenceCountFrom(Address fromAddr) {
		return refs(false) == null
				? 0
				: refs.getReferenceCountFrom(program.snap, fromAddr);
	}

	@Override
	public int getReferenceDestinationCount() {
		// TODO: It is unclear if the interface definition means to include unique addresses
		// or also unique references
		return refs(false) == null
				? 0
				: (int) refs.getReferenceDestinations(Range.closed(program.snap, program.snap))
						.getNumAddresses();
	}

	@Override
	public int getReferenceSourceCount() {
		// TODO: It is unclear if the interface definition means to include unique addresses
		// or also unique references
		return refs(false) == null
				? 0
				: (int) refs.getReferenceSources(Range.closed(program.snap, program.snap))
						.getNumAddresses();
	}

	@Override
	public boolean hasReferencesTo(Address toAddr) {
		return refs(false) == null
				? false
				: !refs.getReferencesTo(program.snap, toAddr).isEmpty();
	}

	@Override
	public Reference updateRefType(Reference ref, RefType refType) {
		DBTraceReference dbRef = refsManager.assertIsMine(ref);
		dbRef.setReferenceType(refType);
		return ref;
	}

	@Override
	public void setAssociation(Symbol s, Reference ref) {
		DBTraceReference dbRef = refsManager.assertIsMine(ref);
		dbRef.setAssociatedSymbol(s);
	}

	@Override
	public void removeAssociation(Reference ref) {
		DBTraceReference dbRef = refsManager.assertIsMine(ref);
		dbRef.clearAssociatedSymbol();
	}

	@Override
	public void delete(Reference ref) {
		DBTraceReference dbRef = refsManager.assertIsMine(ref);
		dbRef.delete();
	}

	/**
	 * Get the reference level for a given reference type
	 * 
	 * TODO: Why is this not a property of {@link RefType}, or a static method of
	 * {@link SymbolUtilities}?
	 * 
	 * Note that this was copy-pasted from {@code BigRefListV0}, and there's an exact copy also in
	 * {@code RefListV0}.
	 * 
	 * @param rt the reference type
	 * @return the reference level
	 */
	public static byte getRefLevel(RefType rt) {
		if (rt == RefType.EXTERNAL_REF) {
			return (byte) SymbolUtilities.EXT_LEVEL;
		}
		if (rt.isCall()) {
			return (byte) SymbolUtilities.SUB_LEVEL;
		}
		if (rt.isData() || rt.isIndirect()) {
			return (byte) SymbolUtilities.DAT_LEVEL;
		}
		if (rt.isFlow()) {
			return (byte) SymbolUtilities.LAB_LEVEL;
		}
		return (byte) SymbolUtilities.UNK_LEVEL;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * To clarify, "reference level" is a sort of priority assigned to each reference type. See,
	 * e.g., {@link SymbolUtilities#SUB_LEVEL}. Each is a byte constant, and greater values imply
	 * higher priority. This method returns the highest priority of any reference to the given
	 * address.
	 * 
	 * TODO: Track this in the database?
	 */
	@Override
	public byte getReferenceLevel(Address toAddr) {
		if (refs(false) == null) {
			return SymbolUtilities.UNK_LEVEL;
		}
		byte highest = SymbolUtilities.UNK_LEVEL;
		for (TraceReference ref : refs.getReferencesTo(program.snap, toAddr)) {
			highest = (byte) Math.max(highest, getRefLevel(ref.getReferenceType()));
		}
		return highest;
	}
}
