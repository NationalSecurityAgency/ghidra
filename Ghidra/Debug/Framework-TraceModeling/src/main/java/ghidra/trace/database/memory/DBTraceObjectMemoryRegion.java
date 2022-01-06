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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetMemoryRegion;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
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
		protected TraceChangeType<TraceMemoryRegion, Range<Long>> getLifespanChangedType() {
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
	}

	private final DBTraceObject object;
	private final RegionChangeTranslator translator;

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
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
			object.getTrace().updateViewsChangeRegionBlockName(this);
		}
	}

	@Override
	public String getName() {
		TraceObjectValue value =
			object.getValue(getCreationSnap(), TargetObject.DISPLAY_ATTRIBUTE_NAME);
		return value == null ? "" : (String) value.getValue();
	}

	@Override
	public void setLifespan(Range<Long> newLifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			Range<Long> oldLifespan = getLifespan();
			if (Objects.equals(oldLifespan, newLifespan)) {
				return;
			}
			TraceObjectInterfaceUtils.setLifespan(TraceObjectMemoryRegion.class, object,
				newLifespan);
			object.getTrace().updateViewsChangeRegionBlockLifespan(this, oldLifespan, newLifespan);
		}
	}

	@Override
	public Range<Long> getLifespan() {
		return object.getLifespan();
	}

	@Override
	public void setCreationSnap(long creationSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(creationSnap, getDestructionSnap()));
		}
	}

	@Override
	public long getCreationSnap() {
		return object.getMinSnap();
	}

	@Override
	public void setDestructionSnap(long destructionSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getCreationSnap(), destructionSnap));
		}
	}

	@Override
	public long getDestructionSnap() {
		return object.getMaxSnap();
	}

	@Override
	public void setRange(AddressRange newRange) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			AddressRange oldRange = getRange();
			if (Objects.equals(oldRange, newRange)) {
				return;
			}
			object.setValue(getLifespan(), TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, newRange);
			object.getTrace().updateViewsChangeRegionBlockRange(this, oldRange, newRange);
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, getCreationSnap(),
				TargetMemoryRegion.RANGE_ATTRIBUTE_NAME, AddressRange.class, null);
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
	public void setFlags(Range<Long> lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : TraceMemoryFlag.values()) {
				Boolean val = flags.contains(flag) ? true : null;
				object.setValue(lifespan, keyForFlag(flag), val);
			}
			object.getTrace().updateViewsChangeRegionBlockFlags(this, lifespan);
		}
	}

	@Override
	public void addFlags(Range<Long> lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : flags) {
				object.setValue(lifespan, keyForFlag(flag), true);
			}
			object.getTrace().updateViewsChangeRegionBlockFlags(this, lifespan);
		}
	}

	@Override
	public void clearFlags(Range<Long> lifespan, Collection<TraceMemoryFlag> flags) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			for (TraceMemoryFlag flag : flags) {
				object.setValue(lifespan, keyForFlag(flag), null);
			}
			object.getTrace().updateViewsChangeRegionBlockFlags(this, lifespan);
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
			object.deleteTree();
			object.getTrace().updateViewsDeleteRegionBlock(this);
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
}
