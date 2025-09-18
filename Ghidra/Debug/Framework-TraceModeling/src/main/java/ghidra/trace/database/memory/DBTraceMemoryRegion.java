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
package ghidra.trace.database.memory;

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceMemoryRegion implements TraceMemoryRegion, DBTraceObjectInterface {

	protected record Keys(Set<String> all, String range, String display,
			Set<String> flags) {
		static Keys fromSchema(TraceObjectSchema schema) {
			String keyRange = schema.checkAliasedAttribute(KEY_RANGE);
			String keyDisplay = schema.checkAliasedAttribute(KEY_DISPLAY);
			String keyReadable = schema.checkAliasedAttribute(KEY_READABLE);
			String keyWritable = schema.checkAliasedAttribute(KEY_WRITABLE);
			String keyExecutable = schema.checkAliasedAttribute(KEY_EXECUTABLE);
			return new Keys(Set.of(keyRange, keyDisplay, keyReadable, keyWritable, keyExecutable),
				keyRange, keyDisplay, Set.of(keyReadable, keyWritable, keyExecutable));
		}

		public boolean isRange(String key) {
			return range.equals(key);
		}

		public boolean isDisplay(String key) {
			return display.equals(key);
		}

		public boolean isFlag(String key) {
			return flags.contains(key);
		}
	}

	protected class RegionChangeTranslator extends Translator<TraceMemoryRegion> {
		private static final Map<TraceObjectSchema, Keys> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Keys keys;

		protected RegionChangeTranslator(DBTraceObject object, TraceMemoryRegion iface) {
			super(KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, Keys::fromSchema);
			}
		}

		@Override
		protected TraceEvent<TraceMemoryRegion, Void> getAddedType() {
			return TraceEvents.REGION_ADDED;
		}

		@Override
		protected TraceEvent<TraceMemoryRegion, Lifespan> getLifespanChangedType() {
			return TraceEvents.REGION_LIFESPAN_CHANGED;
		}

		@Override
		protected TraceEvent<TraceMemoryRegion, Void> getChangedType() {
			return TraceEvents.REGION_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return keys.all.contains(key);
		}

		@Override
		protected TraceEvent<TraceMemoryRegion, Void> getDeletedType() {
			return TraceEvents.REGION_DELETED;
		}

		@Override
		protected void emitExtraAdded() {
			updateViewsAdded();
		}

		@Override
		protected void emitExtraLifespanChanged(Lifespan oldLifespan, Lifespan newLifespan) {
			updateViewsLifespanChanged(oldLifespan, newLifespan);
		}

		@Override
		protected void emitExtraValueChanged(Lifespan lifespan, String key, Object oldValue,
				Object newValue) {
			updateViewsValueChanged(lifespan, key, oldValue, newValue);
		}

		@Override
		protected void emitExtraDeleted() {
			updateViewsDeleted();
		}
	}

	private final DBTraceObject object;
	private final RegionChangeTranslator translator;

	public DBTraceMemoryRegion(DBTraceObject object) {
		this.object = object;

		translator = new RegionChangeTranslator(object, this);
	}

	@Override
	public Trace getTrace() {
		return object.getTrace();
	}

	@Override
	public String getPath() {
		return object.getCanonicalPath().toString();
	}

	@Override
	public void setName(Lifespan lifespan, String name) {
		object.setValue(lifespan, TraceObjectInterface.KEY_DISPLAY, name);
	}

	@Override
	public void setName(long snap, String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(Lifespan.nowOn(snap), name);
		}
	}

	@Override
	public String getName(long snap) {
		String key = object.getCanonicalPath().key();
		String index = KeyPath.parseIfIndex(key);
		return TraceObjectInterfaceUtils.getValue(object, snap, KEY_DISPLAY, String.class, index);
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange newRange) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, KEY_RANGE, newRange);
		}
	}

	@Override
	public void setRange(long snap, AddressRange newRange) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(Lifespan.nowOn(snap), newRange);
		}
	}

	@Override
	public AddressRange getRange(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, snap, KEY_RANGE, AddressRange.class,
				null);
		}
	}

	@Override
	public void setMinAddress(long snap, Address min) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(Lifespan.nowOn(snap), DBTraceUtils.toRange(min, getMaxAddress(snap)));
		}
	}

	@Override
	public Address getMinAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public void setMaxAddress(long snap, Address max) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(Lifespan.nowOn(snap), DBTraceUtils.toRange(getMinAddress(snap), max));
		}
	}

	@Override
	public Address getMaxAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public void setLength(long snap, long length) throws AddressOverflowException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(Lifespan.nowOn(snap), new AddressRangeImpl(getMinAddress(snap), length));
		}
	}

	@Override
	public long getLength(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? 0 : range.getLength();
	}

	protected static String keyForFlag(TraceMemoryFlag flag) {
		return switch (flag) {
			case READ -> KEY_READABLE;
			case WRITE -> KEY_WRITABLE;
			case EXECUTE -> KEY_EXECUTABLE;
			case VOLATILE -> KEY_VOLATILE;
			default -> throw new AssertionError();
		};
	}

	@Override
	public void setFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : TraceMemoryFlag.values()) {
				object.setValue(lifespan, keyForFlag(flag), flags.contains(flag));
			}
		}
	}

	@Override
	public void addFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : flags) {
				object.setValue(lifespan, keyForFlag(flag), true);
			}
		}
	}

	@Override
	public void clearFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : flags) {
				object.setValue(lifespan, keyForFlag(flag), false);
			}
		}
	}

	@Override
	public void setFlags(long snap, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setFlags(Lifespan.nowOn(snap), flags);
		}
	}

	@Override
	public void addFlags(long snap, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			addFlags(Lifespan.nowOn(snap), flags);
		}
	}

	@Override
	public void clearFlags(long snap, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			clearFlags(Lifespan.nowOn(snap), flags);
		}
	}

	@Override
	public Set<TraceMemoryFlag> getFlags(long snap) {
		EnumSet<TraceMemoryFlag> result = EnumSet.noneOf(TraceMemoryFlag.class);
		for (TraceMemoryFlag flag : TraceMemoryFlag.values()) {
			TraceObjectValue value = object.getValue(snap, keyForFlag(flag));
			if (value != null && value.getValue() == Boolean.TRUE) {
				result.add(flag);
			}
		}
		return result;
	}

	@Override
	public void delete() {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(Lifespan.ALL);
		}
	}

	@Override
	public void remove(long snap) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(Lifespan.nowOn(snap));
		}
	}

	@Override
	public boolean isValid(long snap) {
		return object.isAlive(snap);
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}

	protected void updateViewsAdded() {
		object.getTrace().updateViewsAddRegionBlock(this);
	}

	protected void updateViewsLifespanChanged(Lifespan oldLifespan, Lifespan newLifespan) {
		object.getTrace().updateViewsChangeRegionBlockLifespan(this, oldLifespan, newLifespan);
	}

	protected void updateViewsValueChanged(Lifespan lifespan, String key, Object oldValue,
			Object newValue) {
		DBTrace trace = object.getTrace();
		if (translator.keys.isRange(key)) {
			// NB. old/newValue are null here. The CREATED event just has the new entry.
			trace.updateViewsRefreshBlocks();
		}
		else if (translator.keys.isDisplay(key)) {
			trace.updateViewsChangeRegionBlockName(this);
		}
		else if (translator.keys.isFlag(key)) {
			trace.updateViewsChangeRegionBlockFlags(this, lifespan);
		}
	}

	protected void updateViewsDeleted() {
		object.getTrace().updateViewsDeleteRegionBlock(this);
	}
}
