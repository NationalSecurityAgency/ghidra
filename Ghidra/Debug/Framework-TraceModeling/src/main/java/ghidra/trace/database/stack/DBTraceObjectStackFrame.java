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

import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;

public class DBTraceObjectStackFrame implements TraceObjectStackFrame, DBTraceObjectInterface {
	private final DBTraceObject object;

	public DBTraceObjectStackFrame(DBTraceObject object) {
		this.object = object;
	}

	@Override
	public TraceObjectStack getStack() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object
					.queryCanonicalAncestorsInterface(object.getLifespan(), TraceObjectStack.class)
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
				return Integer.parseInt(index, 10); // TODO: How to know the radix?
				// TODO: Perhaps just have an attribute that is its level?
			}
			catch (NumberFormatException e) {
				// fall to preceding key
			}
		}
		throw new IllegalStateException("Frame has no index!?");
	}

	@Override
	public Address getProgramCounter() {
		return TraceObjectInterfaceUtils.getValue(object, object.getMaxSnap(),
			TargetStackFrame.PC_ATTRIBUTE_NAME, Address.class, null);
	}

	@Override
	public void setProgramCounter(Address pc) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			if (pc == Address.NO_ADDRESS) {
				pc = null;
			}
			object.setValue(object.getLifespan(), TargetStackFrame.PC_ATTRIBUTE_NAME, pc);
		}
	}

	@Override
	public String getComment() {
		// TODO: One day, we'll have dynamic columns in the debugger
		/**
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
			Address pc = getProgramCounter();
			return pc == null ? null
					: object.getTrace()
							.getCommentAdapter()
							.getComment(object.getMaxSnap(), pc, CodeUnit.EOL_COMMENT);
		}
	}

	@Override
	public void setComment(String comment) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			object.getTrace()
					.getCommentAdapter()
					.setComment(object.getLifespan(), getProgramCounter(), CodeUnit.EOL_COMMENT,
						comment);
		}
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	protected boolean isPcChange(TraceChangeRecord<?, ?> rec) {
		TraceChangeRecord<TraceObjectValue, Object> cast =
			TraceObjectChangeType.VALUE_CHANGED.cast(rec);
		return TargetStackFrame.PC_ATTRIBUTE_NAME.equals(cast.getAffectedObject().getEntryKey());
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		if (rec.getEventType() == TraceObjectChangeType.CREATED.getType() ||
			rec.getEventType() == TraceObjectChangeType.DELETED.getType() ||
			rec.getEventType() == TraceObjectChangeType.VALUE_CHANGED.getType() &&
				isPcChange(rec)) {
			// NB. Affected object may be the wrapped object, or the value entry
			TraceAddressSpace space =
				spaceForValue(object.getMinSnap(), TargetStackFrame.PC_ATTRIBUTE_NAME);
			return new TraceChangeRecord<>(TraceStackChangeType.CHANGED, space, getStack(), null,
				null);
		}
		return null;
	}
}
