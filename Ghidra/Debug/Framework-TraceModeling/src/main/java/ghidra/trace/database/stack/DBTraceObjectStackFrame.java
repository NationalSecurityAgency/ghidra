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
package ghidra.trace.database.stack;

import java.util.List;

import com.google.common.collect.*;

import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;

public class DBTraceObjectStackFrame implements TraceObjectStackFrame, DBTraceObjectInterface {
	private final DBTraceObject object;
	// TODO: Memorizing life is not optimal.
	// GP-1887 means to expose multiple lifespans in, e.g., TraceThread
	private RangeSet<Long> life = TreeRangeSet.create();

	public DBTraceObjectStackFrame(DBTraceObject object) {
		this.object = object;
	}

	@Override
	public TraceObjectStack getStack() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryCanonicalAncestorsInterface(TraceObjectStack.class)
					.findAny()
					.orElseThrow();
		}
	}

	@Override
	public int getLevel() {
		List<String> keys = object.getCanonicalPath().getKeyList();
		for (int i = keys.size() - 1; i >= 0; i--) {
			String k = keys.get(i);
			if (!PathUtils.isIndex(k)) {
				continue;
			}
			String index = PathUtils.parseIndex(k);
			try {
				return Integer.decode(index);
				// TODO: Perhaps just have an attribute that is its level?
			}
			catch (NumberFormatException e) {
				// fall to preceding key
			}
		}
		throw new IllegalStateException("Frame has no index!?");
	}

	@Override
	public Address getProgramCounter(long snap) {
		return TraceObjectInterfaceUtils.getValue(object, snap,
			TargetStackFrame.PC_ATTRIBUTE_NAME, Address.class, null);
	}

	@Override
	public void setProgramCounter(Range<Long> span, Address pc) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			if (pc == Address.NO_ADDRESS) {
				pc = null;
			}
			object.setValue(span, TargetStackFrame.PC_ATTRIBUTE_NAME, pc);
		}
	}

	@Override
	public String getComment(long snap) {
		// TODO: One day, we'll have dynamic columns in the debugger
		/*
		 * I don't use an attribute for this, because there's not a nice way track the "identity" of
		 * a stack frame. If the frame is re-used (the recommendation for connector development),
		 * the same comment may not necessarily apply. It'd be nice if the connector re-assigned
		 * levels so that identical objects implied identical frames, but that's quite a burden. The
		 * closest identity heuristic is the program counter. Instead of commenting the frame, I'll
		 * comment the memory at the program counter (often, really the return address). Not
		 * perfect, since it may collide with other comments, but a decent approximation that will
		 * follow the "same frame" as its level changes.
		 */
		try (LockHold hold = object.getTrace().lockRead()) {
			Address pc = getProgramCounter(snap);
			return pc == null ? null
					: object.getTrace()
							.getCommentAdapter()
							.getComment(snap, pc, CodeUnit.EOL_COMMENT);
		}
	}

	@Override
	public void setComment(long snap, String comment) {
		/* See rant in getComment */
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectValue pcAttr =
				object.getValue(snap, TargetStackFrame.PC_ATTRIBUTE_NAME);
			object.getTrace()
					.getCommentAdapter()
					.setComment(pcAttr.getLifespan(), (Address) pcAttr.getValue(),
						CodeUnit.EOL_COMMENT, comment);
		}
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	protected boolean changeApplies(TraceChangeRecord<?, ?> rec) {
		TraceChangeRecord<TraceObjectValue, Void> cast =
			TraceObjectChangeType.VALUE_CREATED.cast(rec);
		TraceObjectValue affected = cast.getAffectedObject();
		assert affected.getParent() == object;
		if (!TargetStackFrame.PC_ATTRIBUTE_NAME.equals(affected.getEntryKey())) {
			return false;
		}
		if (object.getCanonicalParent(affected.getMaxSnap()) == null) {
			return false;
		}
		return true;
	}

	@Override
	public Range<Long> computeSpan() {
		Range<Long> span = DBTraceObjectInterface.super.computeSpan();
		if (span != null) {
			return span;
		}
		return getStack().computeSpan();
	}

	protected long snapFor(TraceChangeRecord<?, ?> rec) {
		if (rec.getEventType() == TraceObjectChangeType.VALUE_CREATED.getType()) {
			return TraceObjectChangeType.VALUE_CREATED.cast(rec).getAffectedObject().getMinSnap();
		}
		return computeMinSnap();
	}

	protected TraceChangeRecord<?, ?> createChangeRecord() {
		return new TraceChangeRecord<>(TraceStackChangeType.CHANGED, null, getStack(), 0L,
			DBTraceUtils.lowerEndpoint(life.span()));
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		int type = rec.getEventType();
		if (type == TraceObjectChangeType.LIFE_CHANGED.getType()) {
			RangeSet<Long> newLife = object.getLife();
			if (!newLife.isEmpty()) {
				life = newLife;
			}
			return createChangeRecord();
		}
		else if (type == TraceObjectChangeType.VALUE_CREATED.getType() && changeApplies(rec)) {
			return createChangeRecord();
		}
		else if (type == TraceObjectChangeType.DELETED.getType()) {
			if (life.isEmpty()) {
				return null;
			}
			return createChangeRecord();
		}
		return null;
	}
}
