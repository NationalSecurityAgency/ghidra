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
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.symbol.DBTraceReferenceSpace.DBTraceReferenceEntry;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.symbol.TraceReferenceManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.UnionAddressSetView;
import ghidra.util.database.DBOpenMode;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceReferenceManager extends
		AbstractDBTraceSpaceBasedManager<DBTraceReferenceSpace, DBTraceReferenceRegisterSpace>
		implements TraceReferenceManager, DBTraceDelegatingManager<DBTraceReferenceSpace> {
	public static final String NAME = "Reference";

	public DBTraceReferenceManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager) throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);

		loadSpaces();
	}

	@Override
	protected DBTraceReferenceSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceReferenceSpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceReferenceRegisterSpace createRegisterSpace(AddressSpace space,
			DBTraceThread thread, DBTraceSpaceEntry ent) throws VersionException, IOException {
		return new DBTraceReferenceRegisterSpace(this, dbh, space, ent, thread);
	}

	/**
	 * Ensures that a "from" addresses is in memory
	 * 
	 * NOTE: To manage references from registers, you must use
	 * {@link #getReferenceRegisterSpace(TraceThread, boolean)}, which requires a thread.
	 * 
	 * @param address the address to check
	 */
	@Override
	public void checkIsInMemory(AddressSpace space) {
		if (!space.isMemorySpace()) {
			throw new IllegalArgumentException("Address must be in memory.");
		}
	}

	@Override
	public DBTraceReferenceSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
		return super.getForSpace(space, createIfAbsent);
	}

	@Override
	public Lock readLock() {
		return lock.readLock();
	}

	@Override
	public Lock writeLock() {
		return lock.writeLock();
	}

	protected void doAddXRef(DBTraceReferenceEntry entry) {
		if (!entry.toAddress.isMemoryAddress()) {
			return;
		}
		DBTraceReferenceSpace space = getReferenceSpace(entry.toAddress.getAddressSpace(), true);
		space.doAddXRef(entry);
	}

	protected void doDelXRef(DBTraceReferenceEntry entry) {
		if (!entry.toAddress.isMemoryAddress()) {
			return;
		}
		DBTraceReferenceSpace space = getReferenceSpace(entry.toAddress.getAddressSpace(), false);
		assert space != null;
		space.doDelXRef(entry);
	}

	protected void doSetXRefLifespan(DBTraceReferenceEntry entry) {
		if (!entry.toAddress.isMemoryAddress()) {
			return;
		}
		DBTraceReferenceSpace space = getReferenceSpace(entry.toAddress.getAddressSpace(), false);
		assert space != null;
		space.doSetXRefLifespan(entry);
	}

	// Internal
	public DBTraceReference assertIsMine(Reference ref) {
		if (!(ref instanceof DBTraceReference)) {
			throw new IllegalArgumentException("Given reference is not in this trace");
		}
		DBTraceReference dbRef = (DBTraceReference) ref;
		if (dbRef.ent.space.manager != this) {
			throw new IllegalArgumentException("Given reference is not in this trace");
		}
		return dbRef;
	}

	@Override
	public DBTraceReferenceSpace getReferenceSpace(AddressSpace space, boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceReferenceRegisterSpace getReferenceRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	@Override
	public DBTraceReferenceRegisterSpace getReferenceRegisterSpace(TraceStackFrame frame,
			boolean createIfAbsent) {
		return getForRegisterSpace(frame, createIfAbsent);
	}

	@Override
	public DBTraceReference addReference(TraceReference reference) {
		return delegateWrite(reference.getFromAddress().getAddressSpace(),
			s -> s.addReference(reference));
	}

	@Override
	public DBTraceReference addReference(Range<Long> lifespan, Reference reference) {
		return delegateWrite(reference.getFromAddress().getAddressSpace(),
			s -> s.addReference(lifespan, reference));
	}

	@Override
	public DBTraceReference addMemoryReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, RefType refType, SourceType source, int operandIndex) {
		return delegateWrite(fromAddress.getAddressSpace(), s -> s.addMemoryReference(lifespan,
			fromAddress, toAddress, refType, source, operandIndex));
	}

	@Override
	public DBTraceOffsetReference addOffsetReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, long offset, RefType refType, SourceType source, int operandIndex) {
		return delegateWrite(fromAddress.getAddressSpace(), s -> s.addOffsetReference(lifespan,
			fromAddress, toAddress, offset, refType, source, operandIndex));
	}

	@Override
	public DBTraceShiftedReference addShiftedReference(Range<Long> lifespan, Address fromAddress,
			Address toAddress, int shift, RefType refType, SourceType source, int operandIndex) {
		return delegateWrite(fromAddress.getAddressSpace(), s -> s.addShiftedReference(lifespan,
			fromAddress, toAddress, shift, refType, source, operandIndex));
	}

	@Override
	public DBTraceReference addRegisterReference(Range<Long> lifespan, Address fromAddress,
			Register toRegister, RefType refType, SourceType source, int operandIndex) {
		return delegateWrite(fromAddress.getAddressSpace(), s -> s.addRegisterReference(lifespan,
			fromAddress, toRegister, refType, source, operandIndex));
	}

	@Override
	public DBTraceReference addStackReference(Range<Long> lifespan, Address fromAddress,
			int toStackOffset, RefType refType, SourceType source, int operandIndex) {
		return delegateWrite(fromAddress.getAddressSpace(), s -> s.addStackReference(lifespan,
			fromAddress, toStackOffset, refType, source, operandIndex));
	}

	@Override
	public DBTraceReference getReference(long snap, Address fromAddress, Address toAddress,
			int operandIndex) {
		return delegateRead(fromAddress.getAddressSpace(),
			s -> s.getReference(snap, fromAddress, toAddress, operandIndex));
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap,
			Address fromAddress) {
		return delegateRead(fromAddress.getAddressSpace(),
			s -> s.getReferencesFrom(snap, fromAddress), Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFrom(long snap, Address fromAddress,
			int operandIndex) {
		return delegateRead(fromAddress.getAddressSpace(),
			s -> s.getReferencesFrom(snap, fromAddress, operandIndex), Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesFromRange(Range<Long> span,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), s -> s.getReferencesFromRange(span, range),
			Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceReference> getFlowReferencesFrom(long snap,
			Address fromAddress) {
		return delegateRead(fromAddress.getAddressSpace(),
			s -> s.getFlowReferencesFrom(snap, fromAddress), Collections.emptyList());
	}

	@Override
	public DBTraceReference getPrimaryReferenceFrom(long snap, Address fromAddress,
			int operandIndex) {
		return delegateRead(fromAddress.getAddressSpace(),
			s -> s.getPrimaryReferenceFrom(snap, fromAddress, operandIndex));
	}

	@Override
	public void clearReferencesFrom(Range<Long> span, AddressRange range) {
		delegateDeleteV(range.getAddressSpace(), s -> s.clearReferencesFrom(span, range));
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesTo(long snap, Address toAddress) {
		return delegateRead(toAddress.getAddressSpace(), s -> s.getReferencesTo(snap, toAddress),
			Collections.emptyList());
	}

	@Override
	public Collection<? extends DBTraceReference> getReferencesToRange(Range<Long> span,
			AddressRange range) {
		return delegateRead(range.getAddressSpace(), s -> s.getReferencesToRange(span, range),
			Collections.emptyList());
	}

	@Override
	public AddressSetView getReferenceSources(Range<Long> span) {
		return new UnionAddressSetView(
			Collections2.transform(memSpacesView, s -> s.getReferenceSources(span)));
	}

	@Override
	public AddressSetView getReferenceDestinations(Range<Long> span) {
		return new UnionAddressSetView(
			Collections2.transform(memSpacesView, s -> s.getReferenceDestinations(span)));
	}

	@Override
	public int getReferenceCountFrom(long snap, Address fromAddress) {
		return delegateReadI(fromAddress.getAddressSpace(),
			s -> s.getReferenceCountFrom(snap, fromAddress), 0);
	}

	@Override
	public int getReferenceCountTo(long snap, Address toAddress) {
		return delegateReadI(toAddress.getAddressSpace(),
			s -> s.getReferenceCountTo(snap, toAddress), 0);
	}

	protected Collection<? extends DBTraceReference> getReferencesBySymbolId(long id) {
		// NOTE: Must include register spaces, since this API is not public
		// Only accessed via Symbol, for which it makes sense to include ALL refs.
		return delegateCollection(allSpacesView, m -> m.getReferencesBySymbolId(id));
	}
}
