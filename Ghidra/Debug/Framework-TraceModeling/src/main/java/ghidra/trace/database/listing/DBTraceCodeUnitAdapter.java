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
package ghidra.trace.database.listing;

import static ghidra.lifecycle.Unfinished.TODO;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;

import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.memory.DBTraceMemoryRegion;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.map.TracePropertyMap;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.MemBufferAdapter;
import ghidra.util.LockHold;
import ghidra.util.Saveable;
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;

public interface DBTraceCodeUnitAdapter extends TraceCodeUnit, MemBufferAdapter {

	@Override
	DBTrace getTrace();

	@Override
	default TraceProgramView getProgram() {
		TraceThread thread = getThread();
		TraceProgramView view = getTrace().getProgramView();
		if (thread == null) {
			return view;
		}
		// Non-null: How could a unit be here otherwise?
		return Objects.requireNonNull(view.getViewRegisters(thread, false));
	}

	// TODO: Do I delete comments when code unit is deleted?
	// TODO: Do I adjust lifespan of comments with code unit?
	// TODO: Same two questions for properties
	// I'm leaning toward "no" on all

	@Override
	default String getAddressString(boolean showBlockName, boolean pad) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			Address address = getAddress();
			if (!showBlockName) {
				return address.toString(false, pad);
			}
			DBTraceMemoryRegion region =
				getTrace().getMemoryManager().getRegionContaining(getStartSnap(), address);
			if (region == null) {
				return address.toString(showBlockName, pad);
			}
			return region.getName() + ":" + address.toString(false, pad);
		}
	}

	@Override
	default <T> void setProperty(String name, Class<T> valueClass, T value) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			TracePropertyMap<? super T> setter =
				getTrace().getAddressPropertyManager().getOrCreatePropertySetter(name, valueClass);
			setter.set(getLifespan(), getAddress(), value);
		}
	}

	@Override
	default <T, U extends T> void setTypedProperty(String name, T value) {
		@SuppressWarnings("unchecked")
		Class<U> valueClass = (Class<U>) value.getClass();
		setProperty(name, valueClass, valueClass.cast(value));
	}

	@Override
	default void setProperty(String name, Saveable value) {
		// TODO: It'd be better if the CodeUnit interface took a valueClass variable...
		setTypedProperty(name, value);
	}

	@Override
	default void setProperty(String name, String value) {
		setProperty(name, String.class, value);
	}

	@Override
	default void setProperty(String name, int value) {
		setProperty(name, Integer.class, value);
	}

	@Override
	default void setProperty(String name) {
		setProperty(name, Void.class, null);
	}

	@Override
	default <T> T getProperty(String name, Class<T> valueClass) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			TracePropertyMap<? extends T> getter =
				getTrace().getAddressPropertyManager().getPropertyGetter(name, valueClass);
			return getter.get(getStartSnap(), getAddress());
		}
	}

	@Override
	default Saveable getObjectProperty(String name) {
		return getProperty(name, Saveable.class);
	}

	@Override
	default String getStringProperty(String name) {
		return getProperty(name, String.class);
	}

	@Override
	default int getIntProperty(String name) throws NoValueException {
		Integer value = getProperty(name, Integer.class);
		if (value == null) {
			throw new NoValueException();
		}
		return value;
	}

	@Override
	default boolean hasProperty(String name) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			TracePropertyMap<?> map = getTrace().getAddressPropertyManager().getPropertyMap(name);
			if (map == null) {
				return false;
			}
			// NOTE: Properties all defined at start snap
			return map.getAddressSetView(Range.closed(getStartSnap(), getStartSnap()))
					.contains(getAddress());
		}
	}

	@Override
	default boolean getVoidProperty(String name) {
		// NOTE: Nearly identical to hasProperty, except named property must be Void type
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			TracePropertyMap<? extends Void> getter =
				getTrace().getAddressPropertyManager().getPropertyGetter(name, Void.class);
			if (getter == null) {
				return false;
			}
			return getter.getAddressSetView(Range.closed(getStartSnap(), getStartSnap()))
					.contains(
						getAddress());
		}
	}

	@Override
	default Iterator<String> propertyNames() {
		Range<Long> closed = Range.closed(getStartSnap(), getStartSnap());
		return Iterators.transform(Iterators.filter(
			getTrace().getAddressPropertyManager().getAllProperties().entrySet().iterator(),
			e -> e.getValue().getAddressSetView(closed).contains(getAddress())), Entry::getKey);
	}

	@Override
	default void removeProperty(String name) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().writeLock())) {
			TracePropertyMap<?> map = getTrace().getAddressPropertyManager().getPropertyMap(name);
			if (map == null) {
				return;
			}
			map.clear(getLifespan(), new AddressRangeImpl(getMinAddress(), getMaxAddress()));
		}
	}

	@Override
	default void visitProperty(PropertyVisitor visitor, String propertyName) {
		try (LockHold hold = LockHold.lock(getTrace().getReadWriteLock().readLock())) {
			TracePropertyMap<?> map =
				getTrace().getAddressPropertyManager().getPropertyMap(propertyName);
			if (map == null) {
				return;
			}
			if (map.getValueClass() == Void.class) {
				if (map.getAddressSetView(Range.closed(getStartSnap(), getStartSnap()))
						.contains(
							getAddress())) {
					visitor.visit();
				}
				return;
			}
			Object value = map.get(getStartSnap(), getAddress());
			if (value == null) {
				return;
			}
			if (value instanceof String) {
				visitor.visit((String) value);
			}
			else if (value instanceof Saveable) {
				visitor.visit((Saveable) value);
			}
			else if (value instanceof Integer) {
				visitor.visit(((Integer) value).intValue());
			}
			else {
				visitor.visit(value);
			}
		}
	}

	@Override
	default String getLabel() {
		try (LockHold hold = getTrace().lockRead()) {
			Symbol primary = getPrimarySymbol();
			return primary == null ? null : primary.getName();
		}
	}

	@Override
	default Symbol[] getSymbols() {
		try (LockHold hold = getTrace().lockRead()) {
			Collection<? extends TraceSymbol> at =
				getTrace().getSymbolManager()
						.labelsAndFunctions()
						.getAt(getStartSnap(), getThread(),
							getAddress(), true);
			return at.toArray(new TraceSymbol[at.size()]);
		}
	}

	@Override
	default Symbol getPrimarySymbol() {
		try (LockHold hold = getTrace().lockRead()) {
			Collection<? extends TraceSymbol> at =
				getTrace().getSymbolManager()
						.labelsAndFunctions()
						.getAt(getStartSnap(), getThread(),
							getAddress(), true);
			if (at.isEmpty()) {
				return null;
			}
			return at.iterator().next();
		}
	}

	@Override
	default Address getMinAddress() {
		return getAddress();
	}

	@Override
	default void setComment(int commentType, String comment) {
		if (getThread() != null) {
			TODO(); // TODO: Comments in register space
		}
		getTrace().getCommentAdapter()
				.setComment(getLifespan(), getAddress(), commentType,
					comment);
	}

	@Override
	default String getComment(int commentType) {
		if (getThread() != null) {
			// TODO: Comments in register space
			return null;
		}
		return getTrace().getCommentAdapter().getComment(getStartSnap(), getAddress(), commentType);
	}

	@Override
	default void setCommentAsArray(int commentType, String[] comment) {
		setComment(commentType, DBTraceCommentAdapter.commentFromArray(comment));
	}

	@Override
	default String[] getCommentAsArray(int commentType) {
		return DBTraceCommentAdapter.arrayFromComment(getComment(commentType));
	}

	@Override
	default boolean isSuccessor(CodeUnit codeUnit) {
		return getMaxAddress().isSuccessor(codeUnit.getMinAddress());
	}

	@Override
	default boolean contains(Address testAddr) {
		return getMinAddress().compareTo(testAddr) <= 0 && testAddr.compareTo(getMaxAddress()) <= 0;
	}

	@Override
	default int compareTo(Address addr) {
		if (addr.compareTo(this.getMinAddress()) < 0) {
			return -1;
		}
		if (addr.compareTo(this.getMaxAddress()) > 0) {
			return 1;
		}
		return 0;
	}

	@Override
	default void addMnemonicReference(Address refAddr, RefType refType, SourceType sourceType) {
		getTrace().getReferenceManager()
				.addMemoryReference(getLifespan(), getAddress(), refAddr,
					refType, sourceType, MNEMONIC);
	}

	@Override
	default void addOperandReference(int index, Address refAddr, RefType type,
			SourceType sourceType) {
		getTrace().getReferenceManager()
				.addMemoryReference(getLifespan(), getAddress(), refAddr,
					type, sourceType, index);
	}

	@Override
	default void setPrimaryMemoryReference(Reference ref) {
		DBTraceReference dbRef = getTrace().getReferenceManager().assertIsMine(ref);
		dbRef.setPrimary(true);
	}

	@Override
	default void setStackReference(int opIndex, int offset, SourceType sourceType,
			RefType refType) {
		getTrace().getReferenceManager()
				.addStackReference(getLifespan(), getAddress(), offset,
					refType, sourceType, opIndex);
	}

	@Override
	default void setRegisterReference(int opIndex, Register reg, SourceType sourceType,
			RefType refType) {
		getTrace().getReferenceManager()
				.addRegisterReference(getLifespan(), getAddress(), reg,
					refType, sourceType, opIndex);
	}

	@Override
	default DBTraceReference[] getMnemonicReferences() {
		return getOperandReferences(CodeUnit.MNEMONIC);
	}

	@Override
	default DBTraceReference[] getOperandReferences(int index) {
		Collection<? extends TraceReference> refs =
			getTrace().getReferenceManager().getReferencesFrom(getStartSnap(), getAddress(), index);
		return refs.toArray(new DBTraceReference[refs.size()]);
	}

	@Override
	default DBTraceReference getPrimaryReference(int index) {
		return getTrace().getReferenceManager()
				.getPrimaryReferenceFrom(getStartSnap(), getAddress(),
					index);
	}

	@Override
	default DBTraceReference[] getReferencesFrom() {
		Collection<? extends TraceReference> refs =
			getTrace().getReferenceManager().getReferencesFrom(getStartSnap(), getAddress());
		return refs.toArray(new DBTraceReference[refs.size()]);
	}

	@Override
	default ReferenceIterator getReferenceIteratorTo() {
		return new ReferenceIteratorAdapter(
			getTrace().getReferenceManager()
					.getReferencesTo(getStartSnap(), getAddress())
					.iterator());
	}

	@Override
	default ExternalReference getExternalReference(int opIndex) {
		return null;
	}

	@Override
	default void removeMnemonicReference(Address refAddr) {
		removeOperandReference(CodeUnit.MNEMONIC, refAddr);
	}

	@Override
	default void removeOperandReference(int index, Address refAddr) {
		TraceReference ref =
			getTrace().getReferenceManager()
					.getReference(getStartSnap(), getAddress(), refAddr, index);
		if (ref == null) {
			return;
		}
		ref.delete();
	}

	@Override
	default void removeExternalReference(int opIndex) {
		throw new UnsupportedOperationException();
	}

	@Override
	default Memory getMemory() {
		return getProgram().getMemory();
	}

	@Override
	default boolean isBigEndian() {
		return getLanguage().isBigEndian();
	}

	@Override
	default byte[] getBytes() throws MemoryAccessException {
		return getBytesInFull(0, getLength()).array();
	}

	@Override
	default void getBytesInCodeUnit(byte[] buffer, int bufferOffset) throws MemoryAccessException {
		int len = Math.min(buffer.length - bufferOffset, getLength());
		if (getBytes(ByteBuffer.wrap(buffer, bufferOffset, len), 0) != len) {
			throw new MemoryAccessException("Couldn't get requested bytes for CodeUnit");
		}
	}

}
