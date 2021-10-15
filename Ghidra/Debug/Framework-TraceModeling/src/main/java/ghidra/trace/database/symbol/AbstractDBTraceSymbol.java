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
package ghidra.trace.database.symbol;

import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import db.DBRecord;
import generic.CatenatedCollection;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses;
import ghidra.trace.database.program.DBTraceProgramView;
import ghidra.trace.database.symbol.DBTraceSymbolManager.DBTraceSymbolIDEntry;
import ghidra.trace.database.symbol.DBTraceSymbolManager.MySymbolTypes;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.symbol.TraceSymbol;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.DBAnnotatedColumn;
import ghidra.util.database.annot.DBAnnotatedField;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractDBTraceSymbol extends DBAnnotatedObject
		implements TraceSymbol, DecodesAddresses {

	private static final byte SOURCE_MASK = 0x0F;
	private static final int SOURCE_SHIFT = 0;
	private static final byte SOURCE_CLEAR = ~(SOURCE_MASK << SOURCE_SHIFT);

	private static final byte PRIMARY_MASK = 0x10;
	private static final int PRIMARY_CLEAR = ~PRIMARY_MASK;

	static final String NAME_COLUMN_NAME = "Name";
	static final String PARENT_COLUMN_NAME = "Parent";
	static final String FLAGS_COLUMN_NAME = "Flags";

	@DBAnnotatedColumn(NAME_COLUMN_NAME)
	static DBObjectColumn NAME_COLUMN;
	@DBAnnotatedColumn(PARENT_COLUMN_NAME)
	static DBObjectColumn PARENT_COLUMN;
	@DBAnnotatedColumn(FLAGS_COLUMN_NAME)
	static DBObjectColumn FLAGS_COLUMN;

	@DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
	String name;
	@DBAnnotatedField(column = PARENT_COLUMN_NAME, indexed = true)
	long parentID;
	@DBAnnotatedField(column = FLAGS_COLUMN_NAME)
	byte flags;

	protected DBTraceNamespaceSymbol parent;

	protected final DBTraceSymbolManager manager;

	public AbstractDBTraceSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * NOTE: If the IDs match, then the symbols are considered equal, regardless of their other
	 * attributes. This mechanic seems required to support the whole "placeholder" idea. See
	 * {@link SymbolTable#createSymbolPlaceholder(Address, long)}.
	 */
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof AbstractDBTraceSymbol)) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		AbstractDBTraceSymbol that = (AbstractDBTraceSymbol) obj;
		if (this.getID() == that.getID()) {
			return true;
		}

		if (this.getSymbolType() != that.getSymbolType()) {
			return false;
		}
		if (!this.getName().equals(that.getName())) {
			return false;
		}
		if (!this.getAddress().equals(that.getAddress())) {
			return false;
		}
		if (!Objects.equals(this.getParentSymbol(), that.getParentSymbol())) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(getID());
	}

	@Override
	public String toString() {
		return name;
	}

	protected void assertNotGlobal() {
		if (isGlobal()) {
			throw new UnsupportedOperationException("Cannot modify the global namespace");
		}
	}

	protected DBTraceNamespaceSymbol assertIsNamespace(AbstractDBTraceSymbol symbol) {
		assert symbol != null;
		if (!(symbol instanceof DBTraceNamespaceSymbol)) {
			throw new AssertionError(
				"Trace database corrupted. Symbol has a non-namespace parent.");
		}
		return (DBTraceNamespaceSymbol) symbol;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			return;
		}

		parent = parentID == -1 ? null : assertIsNamespace(manager.getSymbolByID(parentID));
	}

	@Override
	public DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter() {
		return manager.overlayAdapter;
	}

	@Override
	public DBTrace getTrace() {
		return manager.trace;
	}

	@Override
	public DBTraceThread getThread() {
		return null;
	}

	protected TraceAddressSpace getSpace() {
		return null;
	}

	@Override
	public long getID() {
		if (isGlobal()) {
			return GlobalNamespace.GLOBAL_NAMESPACE_ID;
		}
		return DBTraceSymbolManager.packID(getSymbolType().getID(), getKey());
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Address getAddress() {
		return SpecialAddress.NO_ADDRESS;
	}

	protected Collection<? extends TraceAddressSnapRange> getRanges() {
		return new CatenatedCollection<>(Collections2.transform(manager.idMap.getActiveSpaces(),
			space -> Collections2.transform(
				space.getUserIndex(long.class, DBTraceSymbolIDEntry.ID_COLUMN).get(getID()),
				ent -> ent.getShape())));
	}

	// Internal
	public Range<Long> getLifespan() {
		// TODO: Cache this computation and/or keep it as transient fields?
		long min = Long.MAX_VALUE;
		long max = Long.MIN_VALUE;
		for (TraceAddressSnapRange range : getRanges()) {
			min = Math.min(min, DBTraceUtils.lowerEndpoint(range.getLifespan()));
			max = Math.min(max, DBTraceUtils.upperEndpoint(range.getLifespan()));
		}
		if (min > max) {
			return null;
		}
		return DBTraceUtils.toRange(min, max);
	}

	protected void doCollectAddressSet(AddressSet set) {
		for (TraceAddressSnapRange range : getRanges()) {
			set.add(range.getRange());
		}
	}

	// Internal
	public AddressSet getAddressSet() {
		AddressSet result = new AddressSet();
		doCollectAddressSet(result);
		return result;
	}

	@Override
	public String[] getPath() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			checkIsValid();
			if (isGlobal()) {
				return new String[] { getName() };
			}
			ArrayList<String> list = new ArrayList<>();
			if (parent != manager.globalNamespace) {
				parent.doGetPath(list);
			}
			list.add(getName());
			return list.toArray(new String[list.size()]);
		}
	}

	@Override
	public String getName(boolean includeNamespace) {
		if (!includeNamespace) {
			return getName();
		}
		return StringUtils.join(getPath(), "::");
	}

	@Override
	public DBTraceNamespaceSymbol getParentNamespace() {
		return parent;
	}

	@Override
	public DBTraceNamespaceSymbol getParentSymbol() {
		return parent;
	}

	@Override
	public boolean isDescendant(Namespace namespace) {
		for (AbstractDBTraceSymbol s = this; s != null; s = s.parent) {
			if (s == namespace) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Collection<? extends DBTraceReference> getReferenceCollection() {
		return manager.trace.getReferenceManager().getReferencesBySymbolId(getID());
	}

	@Override
	public int getReferenceCount() {
		return getReferenceCollection().size();
	}

	@Override
	public boolean hasMultipleReferences() {
		// TODO: Could be slightly more efficient by just iterating twice?
		return getReferenceCount() > 1;
	}

	@Override
	public boolean hasReferences() {
		return !getReferenceCollection().isEmpty();
	}

	@Override
	public DBTraceReference[] getReferences(TaskMonitor monitor) {
		Collection<? extends DBTraceReference> refs = getReferenceCollection();
		// NOTE: Size computation is just iteration over address spaces. Should be snappy.
		DBTraceReference[] result = new DBTraceReference[refs.size()];
		int i = 0;
		for (DBTraceReference r : refs) {
			result[i++] = r;
			if (monitor.isCancelled()) {
				break;
			}
		}
		return result;
	}

	@Override
	public DBTraceReference[] getReferences() {
		return getReferences(TaskMonitor.DUMMY);
	}

	@SuppressWarnings("hiding")
	void rawSet(String name, long parentID) {
		this.name = name;
		this.parentID = parentID;
		update(NAME_COLUMN, PARENT_COLUMN);
	}

	protected void set(String name, DBTraceNamespaceSymbol parent, SourceType source) {
		this.name = name;
		this.parentID = parent.getID();
		doSetSource(source);
		update(NAME_COLUMN, PARENT_COLUMN, FLAGS_COLUMN);

		this.parent = parent;
	}

	protected TraceChangeRecord<?, ?> doSetNameWithEvent(String newName)
			throws InvalidInputException {
		String oldName = name;
		if (oldName.equals(newName)) {
			return null;
		}
		this.name = newName;
		return new TraceChangeRecord<>(TraceSymbolChangeType.RENAMED, getSpace(), this, oldName,
			newName);
	}

	/**
	 * Checks and sets the parent
	 * 
	 * The caller must still call {@link #update(DBObjectColumn...)} for {@link #PARENT_COLUMN}.
	 * 
	 * @param newParent the parent namespace
	 * @throws CircularDependencyException
	 */
	protected TraceChangeRecord<?, ?> doSetParent(DBTraceNamespaceSymbol newParent)
			throws CircularDependencyException {
		DBTraceNamespaceSymbol oldParent = parent;
		if (oldParent == newParent) {
			return null;
		}
		if (!isValidParent(newParent)) {
			throw new IllegalArgumentException(
				"This symbol type cannot be a child of the given namespace type");
		}
		DBTraceNamespaceSymbol checkedParent = checkCircular(newParent);
		this.parent = checkedParent;
		this.parentID = parent.getID();
		return new TraceChangeRecord<>(TraceSymbolChangeType.PARENT_CHANGED, getSpace(), this,
			oldParent, checkedParent);
	}

	protected void doSetSource(SourceType newSource) {
		flags =
			(byte) ((flags & SOURCE_CLEAR) | (newSource.ordinal() & SOURCE_MASK) << SOURCE_SHIFT);
	}

	/**
	 * Sets the flags for the given source.
	 * 
	 * The caller must still call {@link #update(DBObjectColumn...)} for {@link #FLAGS_COLUMN}. The
	 * update should be called before the returned event, if applicable, is fired.
	 * 
	 * @param newSource the source type
	 * @return the appropriate change event, if a change was actually made
	 */
	protected TraceChangeRecord<?, ?> doSetSourceWithEvent(SourceType newSource) {
		SourceType oldSource = getSource();
		if (oldSource == newSource) {
			return null;
		}
		doSetSource(newSource);
		return new TraceChangeRecord<>(TraceSymbolChangeType.SOURCE_CHANGED, getSpace(), this,
			oldSource, newSource);
	}

	@Override
	public boolean isValidParent(Namespace ns) {
		DBTraceNamespaceSymbol dbns = manager.checkIsMine(ns);
		if (dbns == null) {
			return false;
		}
		return MySymbolTypes.values()[this.getSymbolType().getID()].isValidParent(dbns);
	}

	protected DBTraceNamespaceSymbol checkCircular(DBTraceNamespaceSymbol newParent)
			throws CircularDependencyException {
		return newParent;
	}

	protected Pair<String, SourceType> validateNameAndSource(String newName, SourceType newSource)
			throws InvalidInputException {
		if ((newSource == SourceType.DEFAULT) ^ (getSource() == SourceType.DEFAULT)) {
			throw new IllegalArgumentException("Cannot create or remove DEFAULT symbols");
		}
		DBTraceSymbolManager.assertValidName(newName);
		return new ImmutablePair<>(newName, newSource);
	}

	@Override
	public void setName(String newName, SourceType newSource)
			throws DuplicateNameException, InvalidInputException {
		assertNotGlobal();
		Pair<String, SourceType> validated = validateNameAndSource(newName, newSource);
		newName = validated.getLeft();
		newSource = validated.getRight();
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			TraceChangeRecord<?, ?> nameEvent = doSetNameWithEvent(newName);
			TraceChangeRecord<?, ?> sourceEvent = doSetSourceWithEvent(newSource);
			if (nameEvent != null || sourceEvent != null) {
				update(NAME_COLUMN, FLAGS_COLUMN);
			}
			if (nameEvent != null) {
				manager.trace.setChanged(nameEvent);
			}
			if (sourceEvent != null) {
				manager.trace.setChanged(sourceEvent);
			}
		}
	}

	protected void validateNameAndParent(String newName, DBTraceNamespaceSymbol newParent)
			throws DuplicateNameException {
		manager.assertNotDuplicate(this, newName, newParent);
	}

	@Override
	public void setNamespace(Namespace newNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		// TODO: Why InvalidInputException?
		assertNotGlobal();
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			DBTraceNamespaceSymbol dbnsParent = manager.assertIsMine(newNamespace);
			validateNameAndParent(getName(), dbnsParent);
			TraceChangeRecord<?, ?> parentEvent = doSetParent(dbnsParent);
			if (parentEvent != null) {
				update(PARENT_COLUMN);
				manager.trace.setChanged(parentEvent);
			}
		}
	}

	@Override
	public void setNameAndNamespace(String newName, Namespace newNamespace, SourceType newSource)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		assertNotGlobal();
		Pair<String, SourceType> validated = validateNameAndSource(newName, newSource);
		newName = validated.getLeft();
		newSource = validated.getRight();
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			TraceChangeRecord<?, ?> parentEvent = doSetParent(manager.assertIsMine(newNamespace));
			TraceChangeRecord<?, ?> nameEvent = doSetNameWithEvent(newName);
			TraceChangeRecord<?, ?> sourceEvent = doSetSourceWithEvent(newSource);
			if (parentEvent != null || nameEvent != null || sourceEvent != null) {
				update(NAME_COLUMN, PARENT_COLUMN, FLAGS_COLUMN);
			}
			if (parentEvent != null) {
				manager.trace.setChanged(parentEvent);
			}
			if (nameEvent != null) {
				manager.trace.setChanged(nameEvent);
			}
			if (sourceEvent != null) {
				manager.trace.setChanged(sourceEvent);
			}
		}
	}

	@Override
	public void setSource(SourceType newSource) {
		assertNotGlobal();
		try {
			Pair<String, SourceType> validated = validateNameAndSource(getName(), newSource);
			newSource = validated.getRight();
		}
		catch (InvalidInputException e) {
			throw new AssertionError(e);
		}
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			TraceChangeRecord<?, ?> sourceEvent = doSetSourceWithEvent(newSource);
			if (sourceEvent != null) {
				update(FLAGS_COLUMN);
				manager.trace.setChanged(sourceEvent);
			}
		}
	}

	@Override
	public SourceType getSource() {
		assertNotGlobal();
		return SourceType.values()[(flags >> SOURCE_SHIFT) & SOURCE_MASK];
	}

	@Override
	public boolean delete() {
		assertNotGlobal();
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			return doDelete();
		}
	}

	protected boolean doDelete() {
		return manager.doDeleteSymbol(this);
	}

	@Override
	public boolean isDynamic() {
		return false;
	}

	@Override
	public boolean isGlobal() {
		return parentID == -1;
	}

	@Override
	public DBTraceProgramView getProgram() {
		return manager.trace.getProgramView();
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return new ProgramLocation(getProgram(), getAddress());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Since blocks cannot be relocated as they can in a {@link Program}, it's tempting to say all
	 * symbols are pinned; however, this presents in the UI and is a bit confusing and/or
	 * distracting.
	 */
	@Override
	public boolean isPinned() {
		return false;
	}

	@Override
	public void setPinned(boolean pinned) {
		// Nothing
	}

	@Override
	public boolean isExternal() {
		return false;
	}

	@Override
	public boolean isExternalEntryPoint() {
		return false;
	}
}
