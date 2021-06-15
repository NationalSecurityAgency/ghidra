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
package ghidra.trace.database.context;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.ProgramContextImpl;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.language.DBTraceLanguageManager;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager;
import ghidra.trace.database.space.DBTraceDelegatingManager;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.context.TraceRegisterContextManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceRegisterContextManager extends
		AbstractDBTraceSpaceBasedManager<DBTraceRegisterContextSpace, DBTraceRegisterContextRegisterSpace>
		implements TraceRegisterContextManager,
		DBTraceDelegatingManager<DBTraceRegisterContextSpace> {
	public static final String NAME = "RegisterContext";

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceRegisterContextEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<byte[]> {
		static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		private byte[] value;

		public DBTraceRegisterContextEntry(DBTraceAddressSnapRangePropertyMapTree<byte[], ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(byte[] value) {
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected byte[] getRecordValue() {
			return value;
		}

		void setLifespan(Range<Long> lifespan) {
			super.doSetLifespan(lifespan);
		}
	}

	protected final DBTraceLanguageManager languageManager;

	protected final Map<Language, ProgramContext> defaultContexts = new HashMap<>();

	public DBTraceRegisterContextManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, DBTraceLanguageManager languageManager)
			throws VersionException, IOException {
		super(NAME, dbh, openMode, lock, monitor, baseLanguage, trace, threadManager);
		this.languageManager = languageManager;

		loadSpaces();
	}

	@Override
	protected DBTraceRegisterContextSpace createSpace(AddressSpace space, DBTraceSpaceEntry ent)
			throws VersionException, IOException {
		return new DBTraceRegisterContextSpace(this, dbh, space, ent);
	}

	@Override
	protected DBTraceRegisterContextRegisterSpace createRegisterSpace(AddressSpace space,
			DBTraceThread thread, DBTraceSpaceEntry ent) throws VersionException, IOException {
		// TODO: Should I just forbid this? It doesn't seem sane. Then again, what do I know?
		return new DBTraceRegisterContextRegisterSpace(this, dbh, space, ent, thread);
	}

	@Override
	public DBTraceRegisterContextSpace getForSpace(AddressSpace space, boolean createIfAbsent) {
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

	@Override
	public DBTraceRegisterContextSpace getRegisterContextSpace(AddressSpace space,
			boolean createIfAbsent) {
		return getForSpace(space, createIfAbsent);
	}

	@Override
	public DBTraceRegisterContextRegisterSpace getRegisterContextRegisterSpace(TraceThread thread,
			boolean createIfAbsent) {
		return getForRegisterSpace(thread, 0, createIfAbsent);
	}

	private ProgramContext generateDefaultContext(Language language) {
		ProgramContextImpl context = new ProgramContextImpl(language);
		language.applyContextSettings(context);
		return context;
	}

	// TODO: Internal?
	public ProgramContext getDefaultContext(Language language) {
		return defaultContexts.computeIfAbsent(language, this::generateDefaultContext);
	}

	@Override
	public RegisterValue getDefaultValue(Language language, Register register, Address address) {
		return getDefaultContext(language).getDefaultValue(register, address);
	}

	@Override
	public void setValue(Language language, RegisterValue value, Range<Long> lifespan,
			AddressRange range) {
		delegateWriteV(range.getAddressSpace(), m -> m.setValue(language, value, lifespan, range));
	}

	@Override
	public void removeValue(Language language, Register register, Range<Long> span,
			AddressRange range) {
		delegateDeleteV(range.getAddressSpace(),
			m -> m.removeValue(language, register, span, range));
	}

	@Override
	public RegisterValue getValue(Language language, Register register, long snap,
			Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getValue(language, register, snap, address));
	}

	@Override
	public Entry<TraceAddressSnapRange, RegisterValue> getEntry(Language language,
			Register register, long snap, Address address) {
		return delegateRead(address.getAddressSpace(),
			m -> m.getEntry(language, register, snap, address));
	}

	@Override
	public RegisterValue getValueWithDefault(Language language, Register register, long snap,
			Address address) {
		return delegateReadOr(address.getAddressSpace(),
			m -> m.getValueWithDefault(language, register, snap, address),
			() -> getDefaultValue(language, register, address));
	}

	@Override
	public AddressSetView getRegisterValueAddressRanges(Language language, Register register,
			long snap, AddressRange within) {
		return delegateRead(within.getAddressSpace(),
			m -> m.getRegisterValueAddressRanges(language, register, snap, within),
			new AddressSet());
	}

	@Override
	public AddressSetView getRegisterValueAddressRanges(Language language, Register register,
			long snap) {
		return delegateAddressSet(getActiveMemorySpaces(),
			m -> m.getRegisterValueAddressRanges(language, register, snap));
	}

	@Override
	public boolean hasRegisterValueInAddressRange(Language language, Register register, long snap,
			AddressRange within) {
		return delegateReadB(within.getAddressSpace(),
			m -> m.hasRegisterValueInAddressRange(language, register, snap, within), false);
	}

	@Override
	public boolean hasRegisterValue(Language language, Register register, long snap) {
		return delegateAny(getActiveMemorySpaces(),
			m -> m.hasRegisterValue(language, register, snap));
	}

	@Override
	public void clear(Range<Long> span, AddressRange range) {
		delegateDeleteV(range.getAddressSpace(), m -> m.clear(span, range));
	}
}
