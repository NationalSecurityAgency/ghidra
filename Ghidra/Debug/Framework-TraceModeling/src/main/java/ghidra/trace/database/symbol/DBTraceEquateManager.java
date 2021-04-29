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
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Collections2;
import com.google.common.collect.Range;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceEquateManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;
import ghidra.util.UnionAddressSetView;
import ghidra.util.database.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class DBTraceEquateManager
		extends AbstractDBTraceSpaceBasedManager<DBTraceEquateSpace, DBTraceEquateRegisterSpace>
		implements TraceEquateManager, DBTraceDelegatingManager<DBTraceEquateSpace> {
	public static final String NAME = "Equate";

	protected final DBCachedObjectStore<DBTraceEquate> equateStore;
	protected final Collection<DBTraceEquate> equateView;
	protected final DBCachedObjectIndex<String, DBTraceEquate> equatesByName;
	protected final DBCachedObjectIndex<Long, DBTraceEquate> equatesByValue;

	public DBTraceEquateManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor,
			Language baseLanguage, DBTrace trace, DBTraceThreadManager threadManager)
			throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		equateStore = factory.getOrCreateCachedStore(DBTraceEquate.TABLE_NAME, DBTraceEquate.class,
			(s, r) -> new DBTraceEquate(this, s, r), true);
		equateView = Collections.unmodifiableCollection(equateStore.asMap().values());
		equatesByName = equateStore.getIndex(String.class, DBTraceEquate.NAME_COLUMN);
		equatesByValue = equateStore.getIndex(long.class, DBTraceEquate.VALUE_COLUMN);

		loadSpaces();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			equateStore.invalidateCache();
			super.invalidateCache(all);
		}
	}

	@Override
	public Lock readLock() {
		return lock.readLock();
	}

	@Override
	public Lock writeLock() {
		return lock.writeLock();
	}

	@Override
	public DBTraceEquateSpace getEquateSpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceEquateRegisterSpace getEquateRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceEquateRegisterSpace getEquateRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	protected DBTraceEquateSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceEquateSpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceEquateRegisterSpace createRegisterSpace(AddressSpace space,
			DBTraceThread thread,
			DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceEquateRegisterSpace(this, dbh, space, ent, thread);
	}

	@Override
	public DBTraceEquateSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceEquate create(String newName, long value)
			throws DuplicateNameException, IllegalArgumentException {
		TraceEquateManager.validateName(newName);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceEquate equate = equatesByName.getOne(newName);
			if (equate != null) {
				throw new DuplicateNameException("Equate already exists: " + newName);
			}
			equate = equateStore.create();
			equate.set(newName, value);
			return equate;
		}
	}

	@Override
	public Collection<? extends DBTraceEquate> getAll() {
		return equateView;
	}

	@Override
	public DBTraceEquate getByName(String equateName) {
		return equatesByName.getOne(equateName);
	}

	@Override
	public DBTraceEquate getByKey(long key) {
		return equateStore.getObjectAt(key);
	}

	@Override
	public Collection<? extends DBTraceEquate> getByValue(long value) {
		return Collections.unmodifiableCollection(equatesByValue.get(value));
	}

	protected void doDelete(DBTraceEquate equate) {
		equateStore.delete(equate);
	}

	@Override
	public AddressSetView getReferringAddresses(Range<Long> span) {
		return new UnionAddressSetView(
			Collections2.transform(memSpacesView, m -> m.getReferringAddresses(span)));
	}

	@Override
	public void clearReferences(Range<Long> span, AddressSetView asv, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (AddressRange range : asv) {
				clearReferences(span, range, monitor);
			}
		}
	}

	@Override
	public void clearReferences(Range<Long> span, AddressRange range, TaskMonitor monitor)
			throws CancelledException {
		delegateDeleteV(range.getAddressSpace(), m -> m.clearReferences(span, range, monitor));
	}

	@Override
	public DBTraceEquate getReferencedByValue(long snap, Address address, int operandIndex,
			long value) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getReferencedByValue(snap, address, operandIndex, value));
	}

	@Override
	public Collection<? extends DBTraceEquate> getReferenced(long snap, Address address,
			int operandIndex) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getReferenced(snap, address, operandIndex),
			Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceEquate> getReferenced(long snap, Address address) {
		return delegateRead(address.getAddressSpace(), m -> m.getReferenced(snap, address),
			Collections.emptyList());
	}
}
