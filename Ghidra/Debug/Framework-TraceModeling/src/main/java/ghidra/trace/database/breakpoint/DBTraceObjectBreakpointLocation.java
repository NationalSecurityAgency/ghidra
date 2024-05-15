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

import java.util.*;
import java.util.stream.Collectors;

import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathMatcher;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
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

	protected static class BreakpointChangeTranslator extends Translator<TraceBreakpoint> {
		private static final Map<TargetObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected BreakpointChangeTranslator(DBTraceObject object, TraceBreakpoint iface) {
			super(TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME, object, iface);
			TargetObjectSchema schema = object.getTargetSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					schema.checkAliasedAttribute(TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME),
					schema.checkAliasedAttribute(TargetObject.DISPLAY_ATTRIBUTE_NAME),
					schema.checkAliasedAttribute(TargetTogglable.ENABLED_ATTRIBUTE_NAME),
					schema.checkAliasedAttribute(KEY_COMMENT)));
			}
		}

		@Override
		protected TraceEvent<TraceBreakpoint, Void> getAddedType() {
			return TraceEvents.BREAKPOINT_ADDED;
		}

		@Override
		protected TraceEvent<TraceBreakpoint, Lifespan> getLifespanChangedType() {
			return TraceEvents.BREAKPOINT_LIFESPAN_CHANGED;
		}

		@Override
		protected TraceEvent<TraceBreakpoint, Void> getChangedType() {
			return TraceEvents.BREAKPOINT_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return keys.contains(key);
		}

		@Override
		protected TraceEvent<TraceBreakpoint, Void> getDeletedType() {
			return TraceEvents.BREAKPOINT_DELETED;
		}
	}

	private final DBTraceObject object;
	private final BreakpointChangeTranslator translator;

	// Keep copies here for when the object gets invalidated
	private AddressRange range;
	private Lifespan lifespan;

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
	public void setName(Lifespan lifespan, String name) {
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
			String display = TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
				TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, null);
			if (display != null) {
				return display;
			}
			TraceObject container =
				object.queryCanonicalAncestorsTargetInterface(TargetBreakpointSpecContainer.class)
						.findFirst()
						.orElse(null);
			if (container == null) {
				return ""; // Should be impossible, but maybe not a sane schema
			}
			return container.getCanonicalPath().relativize(object.getCanonicalPath()).toString();
		}
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME, range);
			this.range = range;
		}
	}

	@Override
	public AddressRange getRange() {
		try (LockHold hold = object.getTrace().lockRead()) {
			if (object.getLife().isEmpty()) {
				return range;
			}
			return range = TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
				TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME, AddressRange.class, range);
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
	public void setLifespan(Lifespan lifespan) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectInterfaceUtils.setLifespan(TraceObjectBreakpointLocation.class, object,
				lifespan);
			this.lifespan = lifespan;
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
	public Lifespan computeSpan() {
		Lifespan span = TraceObjectBreakpointLocation.super.computeSpan();
		if (span != null) {
			return span;
		}
		return getSpecification().computeSpan();
	}

	@Override
	public long getPlacedSnap() {
		return getLifespan().lmin();
	}

	@Override
	public void setClearedSnap(long clearedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(Lifespan.span(getPlacedSnap(), clearedSnap));
		}
	}

	@Override
	public long getClearedSnap() {
		return getLifespan().lmax();
	}

	@Override
	public TraceBreakpoint splitAndSet(long snap, boolean enabled,
			Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			if (enabled != isEnabled(snap)) {
				object.setValue(Lifespan.span(snap, getClearedSnap()),
					TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, enabled);
			}
			Set<TraceBreakpointKind> asSet =
				kinds instanceof Set<TraceBreakpointKind> yes ? yes : Set.copyOf(kinds);
			if (!Objects.equals(asSet, getKinds())) {
				this.setKinds(Lifespan.span(snap, getClearedSnap()), asSet);
			}
			return this;
		}
	}

	@Override
	public void setEnabled(Lifespan lifespan, boolean enabled) {
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
				return locEn && getSpecification().isEnabled(snap);
			}
			return getSpecification().isEnabled(snap);
		}
	}

	@Override
	public void setKinds(Lifespan lifespan, Collection<TraceBreakpointKind> kinds) {
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
								TraceObjectThread.class, true))
					.collect(Collectors.toSet());
		}
	}

	@Override
	public void setComment(Lifespan lifespan, String comment) {
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
		try (LockHold hold = object.getTrace().lockRead()) {
			String comment = TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
				KEY_COMMENT, String.class, "");
			if (!comment.isBlank()) {
				return comment;
			}
			TraceObjectBreakpointSpec spec = getSpecification();
			if (spec == null) {
				return "";
			}
			return spec.getExpression();
		}
	}

	@Override
	public void setEmuEnabled(Lifespan lifespan, boolean emuEnabled) {
		object.setValue(lifespan, KEY_EMU_ENABLED, emuEnabled ? null : false);
	}

	@Override
	public void setEmuEnabled(boolean emuEnabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEmuEnabled(getLifespan(), emuEnabled);
		}
	}

	@Override
	public boolean isEmuEnabled(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(), KEY_EMU_ENABLED,
				Boolean.class, true);
		}
	}

	@Override
	public void setEmuSleigh(Lifespan lifespan, String sleigh) {
		if (sleigh == null || SleighUtils.UNCONDITIONAL_BREAK.equals(sleigh)) {
			object.setValue(lifespan, KEY_EMU_SLEIGH, null);
		}
		else {
			object.setValue(lifespan, KEY_EMU_SLEIGH, sleigh.trim());
		}
	}

	@Override
	public void setEmuSleigh(String sleigh) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEmuSleigh(getLifespan(), sleigh);
		}
	}

	@Override
	public String getEmuSleigh() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(), KEY_EMU_SLEIGH,
				String.class, SleighUtils.UNCONDITIONAL_BREAK);
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

	public TraceObjectBreakpointSpec getOrCreateSpecification() {
		return object.queryOrCreateCanonicalAncestorInterface(TraceObjectBreakpointSpec.class);
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
		return spaceForValue(computeMinSnap(), TargetBreakpointLocation.RANGE_ATTRIBUTE_NAME);
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
