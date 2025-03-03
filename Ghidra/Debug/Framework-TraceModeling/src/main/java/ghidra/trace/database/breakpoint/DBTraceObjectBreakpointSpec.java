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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.iface.TraceObjectTogglable;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;
import ghidra.util.Msg;

public class DBTraceObjectBreakpointSpec
		implements TraceObjectBreakpointSpec, DBTraceObjectInterface {
	private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA = new WeakHashMap<>();

	private final DBTraceObject object;
	private final Set<String> keys;

	private TraceBreakpointKindSet kinds = TraceBreakpointKindSet.of();

	public DBTraceObjectBreakpointSpec(DBTraceObject object) {
		this.object = object;
		TraceObjectSchema schema = object.getSchema();
		synchronized (KEYS_BY_SCHEMA) {
			keys = KEYS_BY_SCHEMA.computeIfAbsent(schema,
				s -> Set.of(schema.checkAliasedAttribute(TraceObjectBreakpointSpec.KEY_KINDS),
					schema.checkAliasedAttribute(TraceObjectTogglable.KEY_ENABLED)));
		}
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
	public void setName(long snap, String name) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(Lifespan.nowOn(snap), TraceObjectInterface.KEY_DISPLAY, name);
		}
	}

	@Override
	public String getName(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap, TraceObjectInterface.KEY_DISPLAY,
			String.class, "");
	}

	@Override
	public AddressRange getRange(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public Address getMinAddress(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public Address getMaxAddress(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public long getLength(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public void setEnabled(long snap, boolean enabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(Lifespan.nowOn(snap), TraceObjectTogglable.KEY_ENABLED,
				enabled ? true : null);
		}
	}

	@Override
	public boolean isEnabled(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap,
			TraceObjectTogglable.KEY_ENABLED, Boolean.class, false);
	}

	@Override
	public void setKinds(Lifespan lifespan, Collection<TraceBreakpointKind> kinds) {
		// TODO: More efficient encoding
		// TODO: Target-Trace mapping is implied by encoded name. Seems bad.
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TraceObjectBreakpointSpec.KEY_KINDS,
				TraceBreakpointKindSet.encode(kinds));
			this.kinds = TraceBreakpointKindSet.copyOf(kinds);
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
		String kindsStr = TraceObjectInterfaceUtils.getValue(object, snap,
			TraceObjectBreakpointSpec.KEY_KINDS, String.class, null);
		if (kindsStr == null) {
			return kinds;
		}
		try {
			return kinds = TraceBreakpointKindSet.decode(kindsStr, true);
		}
		catch (IllegalArgumentException e) {
			Msg.warn(this, "Unrecognized breakpoint kind(s) in trace database: " + e);
			return kinds = TraceBreakpointKindSet.decode(kindsStr, false);
		}
	}

	@Override
	public String getExpression(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap,
			TraceObjectBreakpointSpec.KEY_EXPRESSION, String.class, null);
	}

	@Override
	public Set<TraceThread> getThreads(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public void setComment(long snap, String comment) {
		throw new UnsupportedOperationException("Set on a location instead");
	}

	@Override
	public String getComment(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public void setEmuEnabled(long snap, boolean enabled) {
		throw new UnsupportedOperationException("Set on a location instead");
	}

	@Override
	public boolean isEmuEnabled(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public void setEmuSleigh(long snap, String sleigh) {
		throw new UnsupportedOperationException("Set on a location instead");
	}

	@Override
	public String getEmuSleigh(long snap) {
		throw new UnsupportedOperationException("Ask a location instead");
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

	protected Collection<? extends TraceObjectBreakpointLocation> getLocations(Lifespan span) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.querySuccessorsInterface(span, TraceObjectBreakpointLocation.class, true)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public Collection<? extends TraceObjectBreakpointLocation> getLocations(long snap) {
		return getLocations(Lifespan.at(snap));
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		if (rec.getEventType() == TraceEvents.VALUE_CREATED) {
			TraceChangeRecord<TraceObjectValue, Void> cast = TraceEvents.VALUE_CREATED.cast(rec);
			TraceObjectValue affected = cast.getAffectedObject();
			String key = affected.getEntryKey();
			boolean applies = keys.contains(key);
			if (!applies) {
				return null;
			}
			assert affected.getParent() == object;
			if (object.getCanonicalParent(affected.getMaxSnap()) == null) {
				return null; // Incomplete object
			}
			for (TraceObjectBreakpointLocation loc : getLocations(affected.getLifespan())) {
				DBTraceObjectBreakpointLocation dbLoc = (DBTraceObjectBreakpointLocation) loc;
				TraceAddressSpace space = dbLoc.getTraceAddressSpace(affected.getMinSnap());
				TraceChangeRecord<?, ?> evt =
					new TraceChangeRecord<>(TraceEvents.BREAKPOINT_CHANGED, space, loc, null, null);
				object.getTrace().setChanged(evt);
			}
			return null;
		}
		return null;
	}
}
