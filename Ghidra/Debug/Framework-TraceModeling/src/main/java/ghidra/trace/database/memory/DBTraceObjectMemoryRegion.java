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

import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceMemoryRegionChangeType;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectMemoryRegion implements TraceObjectMemoryRegion, DBTraceObjectInterface {

	protected class RegionChangeTranslator extends Translator<TraceMemoryRegion> {
		protected RegionChangeTranslator(DBTraceObject object, TraceMemoryRegion iface) {
			super(TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, object, iface);
		}

		@Override
		protected TraceChangeType<TraceMemoryRegion, Void> getAddedType() {
			return TraceMemoryRegionChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceMemoryRegion, Lifespan> getLifespanChangedType() {
			return TraceMemoryRegionChangeType.LIFESPAN_CHANGED;
		}

		@Override
		protected TraceChangeType<TraceMemoryRegion, Void> getChangedType() {
			return TraceMemoryRegionChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return TargetMemoryRegion.RANGE_ATTRIBUTE_NAME.equals(key) ||
				TargetObject.DISPLAY_ATTRIBUTE_NAME.equals(key) ||
				TargetMemoryRegion.READABLE_ATTRIBUTE_NAME.equals(key) ||
				TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME.equals(key) ||
				TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME.equals(key);
		}

		@Override
		protected TraceChangeType<TraceMemoryRegion, Void> getDeletedType() {
			return TraceMemoryRegionChangeType.DELETED;
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
		object.setValue(lifespan, TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
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
			object.getValue(getCreationSnap(), TargetObject.DISPLAY_ATTRIBUTE_NAME);
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
			object.setValue(lifespan, TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, newRange);
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
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return range = TraceObjectInterfaceUtils.getValue(object, getCreationSnap(),
				TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, AddressRange.class, range);
		}
	}

	@Override
	public void setMinAddress(Address min) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setRange(DBTraceUtils.toRange(min, getMaxAddress()));
		}
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
		switch (flag) {
			case READ:
				return TargetMemoryRegion.READABLE_ATTRIBUTE_NAME;
			case WRITE:
				return TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME;
			case EXECUTE:
				return TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME;
			case VOLATILE:
				return KEY_VOLATILE;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public void setFlags(Lifespan lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : TraceMemoryFlag.values()) {
				Boolean val = flags.contains(flag) ? true : null;
				object.setValue(lifespan, keyForFlag(flag), val);
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
				object.setValue(lifespan, keyForFlag(flag), null);
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
			if (object.getValue(snap, keyForFlag(flag)) != null) {
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
		switch (key) {
			case TargetMemoryRegion.RANGE_ATTRIBUTE_NAME:
				// NB. old/newValue are null here. The CREATED event just has the new entry.
				trace.updateViewsRefreshBlocks();
				return;
			case TargetObject.DISPLAY_ATTRIBUTE_NAME:
				trace.updateViewsChangeRegionBlockName(this);
				return;
			case TargetMemoryRegion.READABLE_ATTRIBUTE_NAME:
			case TargetMemoryRegion.WRITABLE_ATTRIBUTE_NAME:
			case TargetMemoryRegion.EXECUTABLE_ATTRIBUTE_NAME:
				trace.updateViewsChangeRegionBlockFlags(this, lifespan);
				return;
		}
	}

	protected void updateViewsDeleted() {
		object.getTrace().updateViewsDeleteRegionBlock(this);
	}
}
