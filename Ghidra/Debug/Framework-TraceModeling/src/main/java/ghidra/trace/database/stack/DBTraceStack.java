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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceStack implements TraceStack, DBTraceObjectInterface {

	protected class StackChangeTranslator extends Translator<TraceStack> {
		protected StackChangeTranslator(DBTraceObject object, TraceStack iface) {
			super(null, object, iface);
		}

		@Override
		protected TraceEvent<TraceStack, Void> getAddedType() {
			return TraceEvents.STACK_ADDED;
		}

		@Override
		protected TraceEvent<TraceStack, Lifespan> getLifespanChangedType() {
			return null;
		}

		@Override
		protected TraceEvent<TraceStack, ?> getChangedType() {
			return TraceEvents.STACK_CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return false;
		}

		@Override
		protected TraceEvent<TraceStack, Void> getDeletedType() {
			return TraceEvents.STACK_DELETED;
		}
	}

	private final DBTraceObject object;
	private final StackChangeTranslator translator;

	public DBTraceStack(DBTraceObject object) {
		this.object = object;

		translator = new StackChangeTranslator(object, this);
	}

	@Override
	public TraceThread getThread() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryCanonicalAncestorsInterface(TraceThread.class)
					.findAny()
					.orElseThrow();
		}
	}

	@Override
	public int getDepth(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object
					.querySuccessorsInterface(Lifespan.at(snap), TraceStackFrame.class, true)
					.map(f -> f.getLevel())
					.reduce(Integer::max)
					.map(m -> m + 1)
					.orElse(0);
		}
	}

	protected TraceStackFrame doAddStackFrame(long snap, int level) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			PathFilter filter =
				object.getSchema().searchFor(TraceStackFrame.class, true);
			KeyPath relPath = filter.applyKeys(KeyPath.makeIndex(level)).getSingletonPath();
			if (relPath == null) {
				throw new IllegalStateException("Could not determine where to create new frame");
			}
			KeyPath path = object.getCanonicalPath().extend(relPath);
			return object.getManager().addStackFrame(path, snap);
		}
	}

	protected void copyFrameAttributes(long snap, TraceStackFrame from, TraceStackFrame to) {
		// Program Counter is the only attribute?
		to.setProgramCounter(Lifespan.nowOn(snap), from.getProgramCounter(snap));
	}

	protected void shiftFrameAttributes(long snap, int from, int to, int count,
			List<TraceStackFrame> frames) {
		if (from == to) {
			return;
		}
		if (from < to) {
			for (int i = count - 1; i >= 0; i--) {
				copyFrameAttributes(snap, frames.get(from + i), frames.get(to + i));
			}
		}
		else {
			for (int i = 0; i < count; i++) {
				copyFrameAttributes(snap, frames.get(from + i), frames.get(to + i));
			}
		}
	}

	protected void clearFrameAttributes(long snap, int start, int end,
			List<TraceStackFrame> frames) {
		for (int i = start; i < end; i++) {
			TraceStackFrame frame = frames.get(i);
			frame.setProgramCounter(Lifespan.nowOn(snap), null);
		}
	}

	@Override
	public void setDepth(long snap, int depth, boolean atInner) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			List<TraceStackFrame> frames = doGetFrames(snap)
					// Want mutable list
					.collect(Collectors.toCollection(ArrayList::new));
			int curDepth = frames.size();
			if (curDepth == depth) {
				return;
			}
			if (depth < curDepth) {
				if (atInner) {
					int diff = curDepth - depth;
					shiftFrameAttributes(snap, diff, 0, depth, frames);
				}
				for (int i = depth; i < curDepth; i++) {
					frames.get(i).getObject().removeTree(Lifespan.nowOn(snap));
				}
			}
			else {
				for (int i = curDepth; i < depth; i++) {
					frames.add(doAddStackFrame(snap, i));
				}
				if (atInner) {
					int diff = depth - curDepth;
					shiftFrameAttributes(snap, 0, diff, curDepth, frames);
					clearFrameAttributes(snap, 0, diff, frames);
				}
			}
		}
	}

	protected TraceStackFrame doGetFrame(long snap, int level) {
		TraceObjectSchema schema = object.getSchema();
		PathFilter filter = schema.searchFor(TraceStackFrame.class, true);
		PathFilter decFilter = filter.applyKeys(KeyPath.makeIndex(level));
		PathFilter hexFilter = filter.applyKeys("0x" + Integer.toHexString(level));
		Lifespan lifespan = Lifespan.at(snap);
		return object.getSuccessors(lifespan, decFilter)
				.findAny()
				.map(p -> p.getDestination(object).queryInterface(TraceStackFrame.class))
				.or(() -> object.getSuccessors(lifespan, hexFilter)
						.findAny()
						.map(p -> p.getDestination(object).queryInterface(TraceStackFrame.class)))
				.orElse(null);
	}

	@Override
	// This assumes the frame indices are contiguous and include 0
	public TraceStackFrame getFrame(long snap, int level, boolean ensureDepth) {
		if (ensureDepth) {
			try (LockHold hold = object.getTrace().lockWrite()) {
				if (level >= getDepth(snap)) {
					setDepth(snap, level + 1, false);
				}
				return doGetFrame(snap, level);
			}
		}
		try (LockHold hold = object.getTrace().lockRead()) {
			return doGetFrame(snap, level);
		}
	}

	protected Stream<TraceStackFrame> doGetFrames(long snap) {
		return object.querySuccessorsInterface(Lifespan.at(snap), TraceStackFrame.class, true)
				.sorted(Comparator.comparing(f -> f.getLevel()));
	}

	@Override
	public List<TraceStackFrame> getFrames(long snap) {
		try (LockHold hold = object.getTrace().lockRead()) {
			return doGetFrames(snap).collect(Collectors.toList());
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
	public TraceObject getObject() {
		return object;
	}

	@Override
	public TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec) {
		return translator.translate(rec);
	}

	@Override
	public boolean hasFixedFrames() {
		return false;
	}
}
