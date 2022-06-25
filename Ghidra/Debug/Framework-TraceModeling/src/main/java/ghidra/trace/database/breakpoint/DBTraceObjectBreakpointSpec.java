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

import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceBreakpointChangeType;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;

public class DBTraceObjectBreakpointSpec
		implements TraceObjectBreakpointSpec, DBTraceObjectInterface {
	private final DBTraceObject object;

	private TraceBreakpointKindSet kinds;

	public DBTraceObjectBreakpointSpec(DBTraceObject object) {
		this.object = object;
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
		}
	}

	@Override
	public String getName() {
		return TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
			TargetObject.DISPLAY_ATTRIBUTE_NAME, String.class, "");
	}

	@Override
	public AddressRange getRange() {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public Address getMinAddress() {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public Address getMaxAddress() {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public long getLength() {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public Range<Long> getLifespan() {
		return computeSpan();
	}

	@Override
	public long getPlacedSnap() {
		return computeMinSnap();
	}

	@Override
	public void setClearedSnap(long clearedSnap) throws DuplicateNameException {
		try (LockHold hold = object.getTrace().lockWrite()) {
			setLifespan(DBTraceUtils.toRange(getPlacedSnap(), clearedSnap));
		}
	}

	@Override
	public long getClearedSnap() {
		return computeMaxSnap();
	}

	@Override
	public void setLifespan(Range<Long> lifespan) throws DuplicateNameException {
		TraceObjectInterfaceUtils.setLifespan(TraceObjectThread.class, object, lifespan);
	}

	@Override
	public TraceBreakpoint splitAndSet(long snap, boolean enabled,
			Collection<TraceBreakpointKind> kinds) {
		throw new UnsupportedOperationException("Only used by default trace recorder");
	}

	@Override
	public void setEnabled(boolean enabled) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(getLifespan(), TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, enabled);
		}
	}

	@Override
	public boolean isEnabled(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap,
			TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME, Boolean.class, false);
	}

	@Override
	public void setKinds(Range<Long> lifespan, Collection<TraceBreakpointKind> kinds) {
		// TODO: More efficient encoding
		// TODO: Target-Trace mapping is implied by encoded name. Seems bad.
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.setValue(lifespan, TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME,
				TraceBreakpointKindSet.encode(kinds));
			this.kinds = TraceBreakpointKindSet.copyOf(kinds);
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
		String kindsStr = TraceObjectInterfaceUtils.getValue(object, getPlacedSnap(),
			TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME, String.class, null);
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
	public Set<TraceThread> getThreads() {
		throw new UnsupportedOperationException("Ask a location instead");
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException("Set on a location instead");
	}

	@Override
	public String getComment() {
		throw new UnsupportedOperationException("Ask a location instead");
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
	public Collection<? extends TraceObjectBreakpointLocation> getLocations() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object
					.querySuccessorsInterface(getLifespan(), TraceObjectBreakpointLocation.class)
					.collect(Collectors.toSet());
		}
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		if (rec.getEventType() == TraceObjectChangeType.VALUE_CREATED.getType()) {
			TraceChangeRecord<TraceObjectValue, Void> cast =
				TraceObjectChangeType.VALUE_CREATED.cast(rec);
			TraceObjectValue affected = cast.getAffectedObject();
			String key = affected.getEntryKey();
			boolean applies = TargetBreakpointSpec.KINDS_ATTRIBUTE_NAME.equals(key) ||
				TargetBreakpointSpec.ENABLED_ATTRIBUTE_NAME.equals(key);
			if (!applies) {
				return null;
			}
			assert affected.getParent() == object;
			if (object.getCanonicalParent(affected.getMaxSnap()) == null) {
				return null; // Incomplete object
			}
			for (TraceObjectBreakpointLocation loc : getLocations()) {
				DBTraceObjectBreakpointLocation dbLoc = (DBTraceObjectBreakpointLocation) loc;
				TraceAddressSpace space = dbLoc.getTraceAddressSpace();
				TraceChangeRecord<?, ?> evt = new TraceChangeRecord<>(
					TraceBreakpointChangeType.CHANGED, space, loc, null, null);
				object.getTrace().setChanged(evt);
			}
			return null;
		}
		return null;
	}
}
