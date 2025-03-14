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

import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.iface.TraceObjectTogglable;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.*;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceObjectBreakpointLocation
		implements TraceObjectBreakpointLocation, DBTraceObjectInterface {

	protected static class BreakpointChangeTranslator extends Translator<TraceBreakpoint> {
		private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA =
			new WeakHashMap<>();

		private final Set<String> keys;

		protected BreakpointChangeTranslator(DBTraceObject object, TraceBreakpoint iface) {
			super(KEY_RANGE, object, iface);
			TraceObjectSchema schema = object.getSchema();
			synchronized (KEYS_BY_SCHEMA) {
				keys = KEYS_BY_SCHEMA.computeIfAbsent(schema, s -> Set.of(
					schema.checkAliasedAttribute(KEY_RANGE),
					schema.checkAliasedAttribute(KEY_DISPLAY),
					schema.checkAliasedAttribute(TraceObjectTogglable.KEY_ENABLED),
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
		object.setValue(lifespan, KEY_DISPLAY, name);
	}

	@Override
	public void setName(long snap, String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setName(Lifespan.nowOn(snap), name);
		}
	}

	@Override
	public String getName(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			String display =
				TraceObjectInterfaceUtils.getValue(object, snap, KEY_DISPLAY, String.class, null);
			if (display != null) {
				return display;
			}
			TraceObject spec =
				object.findCanonicalAncestorsInterface(TraceObjectBreakpointSpec.class)
						.findFirst()
						.orElse(null);
			if (spec == null) {
				return ""; // Should be impossible, but maybe not a sane schema
			}
			return spec.getCanonicalPath()
					.parent()
					.relativize(object.getCanonicalPath())
					.toString();
		}
	}

	@Override
	public void setRange(Lifespan lifespan, AddressRange range) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, KEY_RANGE, range);
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
	public Address getMinAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMinAddress();
	}

	@Override
	public Address getMaxAddress(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? null : range.getMaxAddress();
	}

	@Override
	public long getLength(long snap) {
		AddressRange range = getRange(snap);
		return range == null ? 0 : range.getLength();
	}

	@Override
	public void setEnabled(Lifespan lifespan, boolean enabled) {
		object.setValue(lifespan, TraceObjectTogglable.KEY_ENABLED, enabled);
	}

	@Override
	public void setEnabled(long snap, boolean enabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEnabled(Lifespan.nowOn(snap), enabled);
		}
	}

	@Override
	public boolean isEnabled(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			Boolean locEn = TraceObjectInterfaceUtils.getValue(object, snap,
				TraceObjectTogglable.KEY_ENABLED, Boolean.class, null);
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
	public void setKinds(long snap, Collection<TraceBreakpointKind> kinds) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setKinds(Lifespan.nowOn(snap), kinds);
		}
	}

	@Override
	public Set<TraceBreakpointKind> getKinds(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return getSpecification().getKinds(snap);
		}
	}

	@Override
	public Set<TraceThread> getThreads(long snap) {
		// TODO: Delete this? It's sort of deprecated out the gate anyway....
		DBTraceObjectManager manager = object.getManager();
		TraceObjectSchema schema = manager.getRootSchema();
		try (LockHold hold = object.getTrace().lockRead()) {
			Set<TraceThread> threads =
				object.queryAncestorsInterface(Lifespan.at(snap), TraceObjectThread.class)
						.collect(Collectors.toSet());
			if (!threads.isEmpty()) {
				return threads;
			}

			PathFilter procFilter = schema.searchFor(TraceObjectProcess.class, false);
			Lifespan lifespan = Lifespan.at(snap);
			return object.getAncestorsRoot(lifespan, procFilter)
					.flatMap(proc -> proc.getSource(object)
							.querySuccessorsInterface(lifespan, TraceObjectThread.class, true))
					.collect(Collectors.toSet());
		}
	}

	@Override
	public void setComment(Lifespan lifespan, String comment) {
		object.setValue(lifespan, KEY_COMMENT, comment);
	}

	@Override
	public void setComment(long snap, String comment) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setComment(Lifespan.nowOn(snap), comment);
		}
	}

	@Override
	public String getComment(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			String comment =
				TraceObjectInterfaceUtils.getValue(object, snap, KEY_COMMENT, String.class, "");
			if (!comment.isBlank()) {
				return comment;
			}
			TraceObjectBreakpointSpec spec = getSpecification();
			if (spec == null) {
				return "";
			}
			return spec.getExpression(snap);
		}
	}

	@Override
	public void setEmuEnabled(Lifespan lifespan, boolean emuEnabled) {
		object.setValue(lifespan, KEY_EMU_ENABLED, emuEnabled ? null : false);
	}

	@Override
	public void setEmuEnabled(long snap, boolean emuEnabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEmuEnabled(Lifespan.nowOn(snap), emuEnabled);
		}
	}

	@Override
	public boolean isEmuEnabled(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, snap, KEY_EMU_ENABLED, Boolean.class,
				true);
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
	public void setEmuSleigh(long snap, String sleigh) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setEmuSleigh(Lifespan.nowOn(snap), sleigh);
		}
	}

	@Override
	public String getEmuSleigh(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return TraceObjectInterfaceUtils.getValue(object, snap, KEY_EMU_SLEIGH, String.class,
				SleighUtils.UNCONDITIONAL_BREAK);
		}
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
	public boolean isAlive(Lifespan span) {
		return object.isAlive(span);
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

	public TraceAddressSpace getTraceAddressSpace(long snap) {
		return spaceForValue(snap, KEY_RANGE);
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}
}
