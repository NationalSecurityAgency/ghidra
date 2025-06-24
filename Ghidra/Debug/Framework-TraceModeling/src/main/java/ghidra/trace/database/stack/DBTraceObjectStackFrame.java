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

import java.util.*;

import ghidra.framework.model.EventType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.DefaultLifeSet;
import ghidra.trace.model.Lifespan.LifeSet;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;

public class DBTraceObjectStackFrame implements TraceObjectStackFrame, DBTraceObjectInterface {
	private static final Map<TraceObjectSchema, Set<String>> KEYS_BY_SCHEMA = new WeakHashMap<>();

	private final DBTraceObject object;
	private final Set<String> keys;

	// TODO: Memorizing life is not optimal.
	// GP-1887 means to expose multiple lifespans in, e.g., TraceThread
	private LifeSet life = new DefaultLifeSet();

	public DBTraceObjectStackFrame(DBTraceObject object) {
		this.object = object;

		TraceObjectSchema schema = object.getSchema();
		synchronized (KEYS_BY_SCHEMA) {
			keys = KEYS_BY_SCHEMA.computeIfAbsent(schema,
				s -> Set.of(schema.checkAliasedAttribute(TraceObjectStackFrame.KEY_PC)));
		}
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
		KeyPath path = object.getCanonicalPath();
		for (int i = path.size() - 1; i >= 0; i--) {
			String k = path.key(i);
			if (!KeyPath.isIndex(k)) {
				continue;
			}
			String index = KeyPath.parseIndex(k);
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
		return TraceObjectInterfaceUtils.getValue(object, snap, TraceObjectStackFrame.KEY_PC,
			Address.class, null);
	}

	@Override
	public void setProgramCounter(Lifespan span, Address pc) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			if (pc == Address.NO_ADDRESS) {
				pc = null;
			}
			object.setValue(span, TraceObjectStackFrame.KEY_PC, pc);
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
					: object.getTrace().getCommentAdapter().getComment(snap, pc, CommentType.EOL);
		}
	}

	@Override
	public void setComment(long snap, String comment) {
		/* See rant in getComment */
		try (LockHold hold = object.getTrace().lockWrite()) {
			TraceObjectValue pcAttr = object.getValue(snap, TraceObjectStackFrame.KEY_PC);
			object.getTrace()
					.getCommentAdapter()
					.setComment(pcAttr.getLifespan(), (Address) pcAttr.getValue(), CommentType.EOL,
						comment);
		}
	}

	@Override
	public TraceObject getObject() {
		return object;
	}

	protected boolean changeApplies(TraceChangeRecord<?, ?> rec) {
		TraceChangeRecord<TraceObjectValue, Void> cast = TraceEvents.VALUE_CREATED.cast(rec);
		TraceObjectValue affected = cast.getAffectedObject();
		assert affected.getParent() == object;
		if (!keys.contains(affected.getEntryKey())) {
			return false;
		}
		if (object.getCanonicalParent(affected.getMaxSnap()) == null) {
			return false;
		}
		return true;
	}

	protected TraceChangeRecord<?, ?> createChangeRecord() {
		return new TraceChangeRecord<>(TraceEvents.STACK_CHANGED, null, getStack(), 0L,
			life.bound().lmin());
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		EventType type = rec.getEventType();
		if (type == TraceEvents.OBJECT_LIFE_CHANGED) {
			LifeSet newLife = object.getLife();
			if (!newLife.isEmpty()) {
				life = newLife;
			}
			return createChangeRecord();
		}
		else if (type == TraceEvents.VALUE_CREATED && changeApplies(rec)) {
			return createChangeRecord();
		}
		else if (type == TraceEvents.OBJECT_DELETED) {
			if (life.isEmpty()) {
				return null;
			}
			return createChangeRecord();
		}
		return null;
	}
}
