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
package ghidra.trace.database.breakpoint;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Range;

import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceBreakpointChangeType;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectBreakpointLocation
		implements TraceObjectBreakpointLocation, DBTraceObjectInterface {

	protected class BreakpointChangeTranslator extends Translator<TraceBreakpoint> {
		protected BreakpointChangeTranslator(DBTraceObject object, TraceBreakpoint iface) {
			super(KEY_RANGE, object, iface);
		}

		@Override
		protected TraceChangeType<TraceBreakpoint, Void> getAddedType() {
			return TraceBreakpointChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceBreakpoint, Range<Long>> getLifespanChangedType() {
			return TraceBreakpointChangeType.LIFESPAN_CHANGED;
		}

		@Override
		protected TraceChangeType<TraceBreakpoint, Void> getChangedType() {
			return TraceBreakpointChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return KEY_RANGE.equals(key) ||
				TargetObject.DISPLAY_ATTRIBUTE_NAME.equals(key) ||
				TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME.equals(key) ||
				KEY_COMMENT.equals(key);
		}

		@Override
		protected TraceChangeType<TraceBreakpoint, Void> getDeletedType() {
			return TraceBreakpointChangeType.DELETED;
		}
	}

	private final DBTraceObject object;
	private final BreakpointChangeTranslator translator;

	// Keep copies here for when the object gets invalidated
	private AddressRange range;
	private Range<Long> lifespan;

	public DBTraceObjectBreakpointLocation(DBTraceObject object) {
		this.object = object;

		translator = new BreakpointChangeTranslator(object, this);
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
	public void setName(Range<Long> lifespan, String name) {
		object.setValue(lifespan, TargetObject.DISPLAY_ATTRIBUTE_NAME, name);
	}

	@Override
	public void setName(String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(getLifespan(), name);
		}
	}

	@Override
	public String getName() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
				TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, "");
		}
	}

	@Override
	public void setRange(Range<Long> lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, KEY_RANGE, range);
			this.range = range;
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return range = TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(), KEY_RANGE,
				AddressRange.class, range);
		}
	}

	@Override
	public Address getMinAddress() {
		AddressRange range = getRange();
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		AddressRange range = getRange();
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public long getLength() {
		AddressRange range = getRange();
		return range == null ? 0 : range.getLength();
	}

	@Override
	public void setLifespan(Range<Long> lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectInterfaceUtils.setLifespan(TraceObjectBreakpointLocation.class, object,
				lifespan);
			this.lifespan = lifespan;
		}
	}

	@Override
	public Range<Long> getLifespan() {
		try (LockHold hold = object.getTrace().lockRead()) {
			Range<Long> computed = computeSpan();
			if (computed != null) {
				lifespan = computed;
			}
			return lifespan;
		}
	}

	@Override
	public Range<Long> computeSpan() {
		Range<Long> span = TraceObjectBreakpointLocation.super.computeSpan();
		if (span != null) {
			return span;
		}
		return getSpecification().computeSpan();
	}

	@Override
	public long getPlacedSnap() {
		return DBTraceUtils.lowerEndpoint(getLifespan());
	}

	@Override
	public void setClearedSnap(long clearedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getPlacedSnap(), clearedSnap));
		}
	}

	@Override
	public long getClearedSnap() {
		return DBTraceUtils.upperEndpoint(getLifespan());
	}

	@Override
	public TraceBreakpoint splitAndSet(long snap, boolean enabled,
			Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			if (enabled != isEnabled(snap)) {
				object.setValue(DBTraceUtils.toRange(snap, getClearedSnap()),
					TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, enabled);
			}
			return this;
		}
	}

	@Override
	public void setEnabled(Range<Long> lifespan, boolean enabled) {
		object.setValue(lifespan, TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, enabled);
	}

	@Override
	public void setEnabled(boolean enabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEnabled(getLifespan(), enabled);
		}
	}

	@Override
	public boolean isEnabled(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			Boolean locEn = TraceObjectInterfaceUtils.getValue(object, snap,
				TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, Boolean.class, null);
			if (locEn != null) {
				return locEn;
			}
			return getSpecification().isEnabled(snap);
		}
	}

	@Override
	public void setKinds(Range<Long> lifespan, Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectBreakpointSpec spec = getSpecification();
			if (spec.getObject() != this.getObject()) {
				throw new UnsupportedOperationException("Set via the specification instead");
			}
			spec.setKinds(lifespan, kinds);
		}
	}

	@Override
	public void setKinds(Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setKinds(getLifespan(), kinds);
		}
	}

	@Override
	public Set<TraceBreakpointKind> getKinds() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return getSpecification().getKinds();
		}
	}

	@Override
	public Set<TraceThread> getThreads() {
		// TODO: Delete this? It's sort of deprecated out the gate anyway....
		DBTraceObjectManager manager = object.getManager();
		TargetObjectSchema schema = manager.getRootSchema();
		try (LockHold hold = object.getTrace().lockRead()) {
			Set<TraceThread> threads =
				object.queryAncestorsInterface(getLifespan(), TraceObjectThread.class)
						.collect(Collectors.toSet());
			if (!threads.isEmpty()) {
				return threads;
			}

			PathMatcher procMatcher = schema.searchFor(TargetProcess.class, false);
			return object.getAncestorsRoot(getLifespan(), procMatcher)
					.flatMap(proc -> proc.getSource(object)
							.querySuccessorsInterface(getLifespan(),
								TraceObjectThread.class))
					.collect(Collectors.toSet());
		}
	}

	@Override
	public void setComment(Range<Long> lifespan, String comment) {
		object.setValue(lifespan, KEY_COMMENT, comment);
	}

	@Override
	public void setComment(String comment) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setComment(getLifespan(), comment);
		}
	}

	@Override
	public String getComment() {
		return TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(), KEY_COMMENT,
			String.class, "");
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
	public TraceObjectBreakpointSpec getSpecification() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryCanonicalAncestorsInterface(TraceObjectBreakpointSpec.class)
					.findAny()
					.orElseThrow();
		}
	}

	public TraceAddressSpace getTraceAddressSpace() {
		return spaceForValue(computeMinSnap(), KEY_RANGE);
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
