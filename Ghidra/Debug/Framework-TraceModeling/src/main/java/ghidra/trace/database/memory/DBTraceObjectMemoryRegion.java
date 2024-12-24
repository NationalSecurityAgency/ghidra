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
import ghidra.trace.model.memory.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectMemoryRegion implements TraceObjectMemoryRegion, DBTraceObjectInterface {

	protected record Keys(Set<String> all, String range, String display,
			Set<String> flags) {
		static Keys fromSchema(TraceObjectSchema schema) {
			String keyRange = schema.checkAliasedAttribute(TraceObjectMemoryRegion.KEY_RANGE);
			String keyDisplay = schema.checkAliasedAttribute(TraceObjectInterface.KEY_DISPLAY);
			String keyReadable =
				schema.checkAliasedAttribute(TraceObjectMemoryRegion.KEY_READABLE);
			String keyWritable =
				schema.checkAliasedAttribute(TraceObjectMemoryRegion.KEY_WRITABLE);
			String keyExecutable =
				schema.checkAliasedAttribute(TraceObjectMemoryRegion.KEY_EXECUTABLE);
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
			super(TraceObjectMemoryRegion.KEY_RANGE, object, iface);
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

	// Keep copies here for when the object gets invalidated
	private AddressRange range;
	private Lifespan lifespan;

	public DBTraceObjectMemoryRegion(DBTraceObject object) {
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
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(computeSpan(), name);
		}
	}

	@Override
	public String getName() {
		TraceObjectValue value =
			object.getValue(getCreationSnap(), TraceObjectInterface.KEY_DISPLAY);
		return value == null ? "" : (String) value.getValue();
	}

	@Override
	public void setLifespan(Lifespan newLifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectInterfaceUtils.setLifespan(TraceObjectMemoryRegion.class, object,
				newLifespan);
			this.lifespan = newLifespan;
		}
	}

	@Override
	public Lifespan getLifespan() {
		try (LockHold hold = object.getTrace().lockRead()) {
			Lifespan computed = computeSpan();
			if (computed != null) {
				lifespan = computed;
			}
			return lifespan;
		}
	}

	@Override
	public void setCreationSnap(long creationSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(creationSnap, getDestructionSnap()));
		}
	}

	@Override
	public long getCreationSnap() {
		return computeMinSnap();
	}

	@Override
	public void setDestructionSnap(long destructionSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(getCreationSnap(), destructionSnap));
		}
	}

	@Override
	public long getDestructionSnap() {
		return computeMaxSnap();
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange newRange) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TraceObjectMemoryRegion.KEY_RANGE, newRange);
			this.range = newRange;
		}
	}

	@Override
	public void setRange(AddressRange newRange) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(computeSpan(), newRange);
		}
	}

	@Override
	public AddressRange getRange(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			// TODO: Caching without regard to snap seems bad
			return range = TraceObjectInterfaceUtils.getValue(object, snap,
				TraceObjectMemoryRegion.KEY_RANGE, AddressRange.class, range);
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return getRange(getCreationSnap());
		}
	}

	@Override
	public void setMinAddress(Address min) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(DBTraceUtils.toRange(min, getMaxAddress()));
		}
	}

	@Override
	public Address getMinAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public Address getMinAddress() {
		AddressRange range = getRange();
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public void setMaxAddress(Address max) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(DBTraceUtils.toRange(getMinAddress(), max));
		}
	}

	@Override
	public Address getMaxAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public Address getMaxAddress() {
		AddressRange range = getRange();
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public void setLength(long length) throws AddressOverflowException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(new AddressRangeImpl(getMinAddress(), length));
		}
	}

	@Override
	public long getLength() {
		return getRange().getLength();
	}

	protected static String keyForFlag(TraceMemoryFlag flag) {
		return switch (flag) {
			case READ -> TraceObjectMemoryRegion.KEY_READABLE;
			case WRITE -> TraceObjectMemoryRegion.KEY_WRITABLE;
			case EXECUTE -> TraceObjectMemoryRegion.KEY_EXECUTABLE;
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
	public void setFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setFlags(getLifespan(), flags);
		}
	}

	@Override
	public void addFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			addFlags(getLifespan(), flags);
		}
	}

	@Override
	public void clearFlags(Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			clearFlags(getLifespan(), flags);
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
	public Set<TraceMemoryFlag> getFlags() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return getFlags(getCreationSnap());
		}
	}

	@Override
	public void delete() {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.removeTree(computeSpan());
		}
	}

	@Override
	public boolean isValid(long snap) {
		return object.getCanonicalParent(snap) != null;
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
