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
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.locks.ReadWriteLock;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import com.google.common.collect.Range;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.context.DBTraceRegisterContextManager.DBTraceRegisterContextEntry;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapAddressSetView;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.context.TraceRegisterContextSpace;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;

public class DBTraceRegisterContextSpace implements TraceRegisterContextSpace, DBTraceSpaceBased {
	protected static final String TABLE_NAME = "RegisterContext";

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceRegisterEntry extends DBAnnotatedObject {
		static final String LANGUAGE_COLUMN_NAME = "Language";
		static final String REGISTER_COLUMN_NAME = "Register";

		@DBAnnotatedColumn(LANGUAGE_COLUMN_NAME)
		static DBObjectColumn LANGUAGE_COLUMN;
		@DBAnnotatedColumn(REGISTER_COLUMN_NAME)
		static DBObjectColumn REGISTER_COLUMN;

		@DBAnnotatedField(column = LANGUAGE_COLUMN_NAME)
		private int langKey;
		@DBAnnotatedField(column = REGISTER_COLUMN_NAME)
		private String register;

		private DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry> map;

		public DBTraceRegisterEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		void set(int langKey, Register register) {
			this.langKey = langKey;
			this.register = register.getName();
			update(LANGUAGE_COLUMN, REGISTER_COLUMN);
		}
	}

	protected final DBTraceRegisterContextManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;
	protected final AddressRange all;

	protected final DBCachedObjectStore<DBTraceRegisterEntry> registerStore;
	protected final Map<Pair<Language, Register>, DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry>> registerValueMaps =
		new HashMap<>();

	public DBTraceRegisterContextSpace(DBTraceRegisterContextManager manager, DBHandle dbh,
			AddressSpace space, DBTraceSpaceEntry ent) throws VersionException, IOException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.lock = manager.getLock();
		this.baseLanguage = manager.getBaseLanguage();
		this.trace = manager.getTrace();
		this.all = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		registerStore = factory.getOrCreateCachedStore(
			DBTraceUtils.tableName(TABLE_NAME, space, ent.getThreadKey(), ent.getFrameLevel()),
			DBTraceRegisterEntry.class, DBTraceRegisterEntry::new, true);

		loadRegisterValueMaps();
	}

	protected void loadRegisterValueMaps() throws VersionException {
		for (DBTraceRegisterEntry ent : registerStore.asMap().values()) {
			Language language = manager.languageManager.getLanguageByKey(ent.langKey);
			Register register = language.getRegister(ent.register);
			ImmutablePair<Language, Register> pair = new ImmutablePair<>(language, register);
			if (ent.map == null) {
				ent.map = createRegisterValueMap(pair);
			}
			registerValueMaps.put(pair, ent.map);
		}
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public DBTraceThread getThread() {
		return null;
	}

	protected long getThreadKey() {
		DBTraceThread thread = getThread();
		return thread == null ? -1 : thread.getKey();
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	protected String tableName(Language language, Register register) {
		return DBTraceUtils.tableName(TABLE_NAME, space, getThreadKey(), getFrameLevel()) + "_" +
			language.getLanguageID().getIdAsString() + "_" + register.getName();
	}

	protected DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry> createRegisterValueMap(
			Pair<Language, Register> lr) throws VersionException {
		String name = tableName(lr.getLeft(), lr.getRight());
		try {
			return new DBTraceAddressSnapRangePropertyMapSpace<>(name, trace.getStoreFactory(),
				lock, space, DBTraceRegisterContextEntry.class, DBTraceRegisterContextEntry::new);
		}
		catch (IOException e) {
			manager.dbError(e);
			return null;
		}
	}

	protected DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry> getRegisterValueMap(
			Language language, Register register, boolean createIfAbsent) {
		ImmutablePair<Language, Register> pair = new ImmutablePair<>(language, register);
		int langKey = manager.languageManager.getKeyForLanguage(language);
		if (createIfAbsent) {
			return registerValueMaps.computeIfAbsent(pair, t -> {
				try {
					DBTraceRegisterEntry ent = registerStore.create();
					ent.set(langKey, register);
					return createRegisterValueMap(t);
				}
				catch (VersionException e) {
					throw new AssertionError(e);
				}
			});
		}
		return registerValueMaps.get(pair);
	}

	protected Set<TraceAddressSnapRange> doSubtract(TraceAddressSnapRange from,
			TraceAddressSnapRange remove) {
		Set<TraceAddressSnapRange> diff = new HashSet<>();
		if (remove.encloses(from)) {
			return diff;
		}
		if (!remove.intersects(from)) {
			diff.add(from);
			return diff;
		}
		TraceAddressSnapRange inter = from.intersection(remove);
		// TODO: See how this performs in practice.
		// TODO: Consider optimizing cover (merging) in a "pack" operation?

		// Note prefer horizontal spans
		if (from.getX1().compareTo(inter.getX1()) < 0) {
			diff.add(new ImmutableTraceAddressSnapRange(from.getX1(), inter.getX1().previous(),
				inter.getLifespan()));
		}
		if (from.getX2().compareTo(inter.getX2()) > 0) {
			diff.add(new ImmutableTraceAddressSnapRange(inter.getX2().next(), from.getX2(),
				inter.getLifespan()));
		}
		if (from.getY1().compareTo(inter.getY1()) < 0) {
			diff.add(new ImmutableTraceAddressSnapRange(from.getRange(),
				Range.closed(from.getY1(), inter.getY1() - 1)));
		}
		if (from.getY2().compareTo(inter.getY2()) > 0) {
			diff.add(new ImmutableTraceAddressSnapRange(from.getRange(),
				Range.closed(inter.getY2() + 1, from.getY2())));
		}
		return diff;
	}

	protected void doPut(DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap,
			TraceAddressSnapRange range, byte[] bytes) {
		doRemove(valueMap, range);
		valueMap.put(range, bytes);
	}

	protected void doRemove(DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap,
			TraceAddressSnapRange range) {
		Map<TraceAddressSnapRange, byte[]> toPutBack = new HashMap<>();
		for (Entry<TraceAddressSnapRange, byte[]> entry : valueMap.reduce(
			TraceAddressSnapRangeQuery.intersecting(range)).entries()) {
			for (TraceAddressSnapRange diff : doSubtract(entry.getKey(), range)) {
				toPutBack.put(diff, entry.getValue());
			}
			valueMap.remove(entry);
		}
		for (Entry<TraceAddressSnapRange, byte[]> entry : toPutBack.entrySet()) {
			valueMap.put(entry.getKey(), entry.getValue());
		}
	}

	protected void doSetBaseValue(Language language, RegisterValue baseValue, Range<Long> lifespan,
			AddressRange range) {
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(range, lifespan);
		Register base = baseValue.getRegister();
		DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
			getRegisterValueMap(language, base, true);
		// Take shortcuts if I'm writing entire base register, or NOPing
		if (baseValue.hasValue()) {
			doPut(valueMap, tasr, baseValue.toBytes());
			return;
		}
		else if (!baseValue.hasAnyValue()) {
			return; // NOP
		}

		// Otherwise, combine with existing values
		HashMap<TraceAddressSnapRange, byte[]> existing = new HashMap<>();
		for (Entry<TraceAddressSnapRange, byte[]> entry : valueMap.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, lifespan)).entries()) {
			existing.put(entry.getKey(), entry.getValue());
		}
		doPut(valueMap, tasr, baseValue.toBytes());
		for (Entry<TraceAddressSnapRange, byte[]> entry : existing.entrySet()) {
			RegisterValue exists = new RegisterValue(base, entry.getValue());
			TraceAddressSnapRange inter = entry.getKey().intersection(tasr);
			doPut(valueMap, inter, exists.combineValues(baseValue).toBytes());
		}
	}

	@Override
	public void setValue(Language language, RegisterValue value, Range<Long> lifespan,
			AddressRange range) {
		assertInSpace(range);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			doSetBaseValue(language, value.getBaseRegisterValue(), lifespan, range);
		}
		// TODO: Fire event
	}

	@Override
	public void removeValue(Language language, Register register, Range<Long> span,
			AddressRange range) {
		Register base = register.getBaseRegister();
		TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(range, span);
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
				getRegisterValueMap(language, base, false);
			if (valueMap == null) {
				return;
			}
			// Take shortcut if I'm writing entire base register
			if (register.isBaseRegister()) {
				doRemove(valueMap, tasr);
			}

			// Otherwise, clear out bits in sub-register
			HashMap<TraceAddressSnapRange, byte[]> existing = new HashMap<>();
			for (Entry<TraceAddressSnapRange, byte[]> entry : valueMap.reduce(
				TraceAddressSnapRangeQuery.intersecting(range, span)).entries()) {
				existing.put(entry.getKey(), entry.getValue());
			}
			for (Entry<TraceAddressSnapRange, byte[]> entry : existing.entrySet()) {
				RegisterValue exists = new RegisterValue(base, entry.getValue());
				RegisterValue cleared = exists.clearBitValues(register.getBaseMask());
				TraceAddressSnapRange inter = entry.getKey().intersection(tasr);
				if (!cleared.hasAnyValue()) {
					doRemove(valueMap, inter);
				}
				else {
					doPut(valueMap, inter, cleared.toBytes());
				}
			}
		}
		// TODO: Fire event
	}

	@Override
	public RegisterValue getDefaultValue(Language language, Register register, Address address) {
		return manager.getDefaultContext(language).getDefaultValue(register, address);
	}

	protected RegisterValue doGetBaseValue(Language language, Register base, long snap,
			Address address) {
		DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
			getRegisterValueMap(language, base, false);
		if (valueMap == null) {
			return null;
		}
		byte[] valueBytes =
			valueMap.reduce(TraceAddressSnapRangeQuery.at(address, snap)).firstValue();
		if (valueBytes == null) {
			return null;
		}
		return new RegisterValue(base, valueBytes);
	}

	@Override
	public RegisterValue getValue(Language language, Register register, long snap,
			Address address) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			RegisterValue baseValue =
				doGetBaseValue(language, register.getBaseRegister(), snap, address);
			if (baseValue == null) {
				return null;
			}
			return baseValue.getRegisterValue(register);
		}
	}

	@Override
	public Entry<TraceAddressSnapRange, RegisterValue> getEntry(Language language,
			Register register, long snap, Address address) {
		Register base = register.getBaseRegister();
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
				getRegisterValueMap(language, base, false);
			if (valueMap == null) {
				return null;
			}
			Entry<TraceAddressSnapRange, byte[]> valueEntry =
				valueMap.reduce(TraceAddressSnapRangeQuery.at(address, snap)).firstEntry();
			if (valueEntry == null) {
				return null;
			}
			return new ImmutablePair<>(valueEntry.getKey(),
				new RegisterValue(base, valueEntry.getValue()));
		}
	}

	@Override
	public RegisterValue getValueWithDefault(Language language, Register register, long snap,
			Address address) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			Register base = register.getBaseRegister();
			RegisterValue baseValue = doGetBaseValue(language, base, snap, address);
			if (baseValue == null) {
				return getDefaultValue(language, register, address);
			}
			RegisterValue defaultBaseValue = getDefaultValue(language, base, address);
			if (defaultBaseValue == null) {
				return baseValue.getRegisterValue(register);
			}
			return defaultBaseValue.combineValues(baseValue).getRegisterValue(register);
		}
	}

	@Override
	public AddressSetView getRegisterValueAddressRanges(Language language, Register register,
			long snap, AddressRange within) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			Register base = register.getBaseRegister();
			DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
				getRegisterValueMap(language, register, false);
			if (valueMap == null) {
				return new AddressSet();
			}
			return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(within.getAddressSpace(),
				lock,
				valueMap.reduce(
					TraceAddressSnapRangeQuery.intersecting(within, Range.closed(snap, snap))),
				val -> new RegisterValue(base, val).getRegisterValue(register).hasAnyValue());
		}
	}

	@Override
	public AddressSetView getRegisterValueAddressRanges(Language language, Register register,
			long snap) {
		return getRegisterValueAddressRanges(language, register, snap, all);
	}

	@Override
	public boolean hasRegisterValueInAddressRange(Language language, Register register, long snap,
			AddressRange within) {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			Register base = register.getBaseRegister();
			DBTraceAddressSnapRangePropertyMapSpace<byte[], ?> valueMap =
				getRegisterValueMap(language, register, false);
			if (valueMap == null) {
				return false;
			}
			for (Entry<TraceAddressSnapRange, byte[]> entry : valueMap.reduce(
				TraceAddressSnapRangeQuery.intersecting(within,
					Range.closed(snap, snap))).entries()) {
				RegisterValue baseValue = new RegisterValue(base, entry.getValue());
				if (baseValue.getRegisterValue(register).hasAnyValue()) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public boolean hasRegisterValue(Language language, Register register, long snap) {
		return hasRegisterValueInAddressRange(language, register, snap, all);
	}

	@Override
	public void clear(Range<Long> span, AddressRange range) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			for (DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry> valueMap : registerValueMaps
					.values()) {
				for (Entry<TraceAddressSnapRange, byte[]> entry : valueMap.reduce(
					TraceAddressSnapRangeQuery.intersecting(range, span)).entries()) {
					DBTraceRegisterContextEntry record =
						(DBTraceRegisterContextEntry) entry.getKey();
					DBTraceUtils.makeWay(record, span, (e, s) -> e.setLifespan(s),
						e -> valueMap.deleteData(record));
				}
			}
		}
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			registerStore.invalidateCache();
			loadRegisterValueMaps();
			for (DBTraceAddressSnapRangePropertyMapSpace<byte[], DBTraceRegisterContextEntry> map : registerValueMaps
					.values()) {
				map.invalidateCache();
			}
		}
		catch (VersionException e) {
			throw new AssertionError(e);
		}
	}
}
