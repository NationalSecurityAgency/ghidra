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
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.path.*;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.*;
import ghidra.util.LockHold;

public class DBTraceObjectStack implements TraceObjectStack, DBTraceObjectInterface {

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

	public DBTraceObjectStack(DBTraceObject object) {
		this.object = object;

		translator = new StackChangeTranslator(object, this);
	}

	@Override
	public TraceThread getThread() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.queryAncestorsInterface(computeSpan(), TraceObjectThread.class)
					.findAny()
					.orElseThrow();
		}
	}

	@Override
	public long getSnap() {
		return computeMinSnap();
	}

	@Override
	public int getDepth() {
		try (LockHold hold = object.getTrace().lockRead()) {
			return object.querySuccessorsInterface(computeSpan(), TraceObjectStackFrame.class, true)
					.map(f -> f.getLevel())
					.reduce(Integer::max)
					.map(m -> m + 1)
					.orElse(0);
		}
	}

	protected TraceObjectStackFrame doAddStackFrame(int level) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			PathMatcher matcher =
				object.getSchema().searchFor(TraceObjectStackFrame.class, true);
			KeyPath relPath = matcher.applyKeys(KeyPath.makeIndex(level)).getSingletonPath();
			if (relPath == null) {
				throw new IllegalStateException("Could not determine where to create new frame");
			}
			KeyPath path = object.getCanonicalPath().extend(relPath);
			return object.getManager().addStackFrame(path, getSnap());
		}
	}

	protected void copyFrameAttributes(TraceObjectStackFrame from, TraceObjectStackFrame to) {
		// TODO: All attributes within a given span, intersected to that span?
		to.setProgramCounter(computeSpan(), from.getProgramCounter(computeMaxSnap()));
	}

	protected void shiftFrameAttributes(int from, int to, int count,
			List<TraceObjectStackFrame> frames) {
		if (from == to) {
			return;
		}
		if (from < to) {
			for (int i = count - 1; i >= 0; i--) {
				copyFrameAttributes(frames.get(from + i), frames.get(to + i));
			}
		}
		else {
			for (int i = 0; i < count; i++) {
				copyFrameAttributes(frames.get(from + i), frames.get(to + i));
			}
		}
	}

	protected void clearFrameAttributes(int start, int end, List<TraceObjectStackFrame> frames) {
		for (int i = start; i < end; i++) {
			TraceObjectStackFrame frame = frames.get(i);
			frame.setProgramCounter(frame.computeSpan(), null);
		}
	}

	@Override
	public void setDepth(int depth, boolean atInner) {
		// TODO: Need a span parameter
		try (LockHold hold = object.getTrace().lockWrite()) {
			List<TraceObjectStackFrame> frames = // Want mutable list
				doGetFrames(computeMinSnap()).collect(Collectors.toCollection(ArrayList::new));
			int curDepth = frames.size();
			if (curDepth == depth) {
				return;
			}
			if (depth < curDepth) {
				if (atInner) {
					int diff = curDepth - depth;
					shiftFrameAttributes(diff, 0, depth, frames);
				}
				for (int i = depth; i < curDepth; i++) {
					frames.get(i).getObject().removeTree(computeSpan());
				}
			}
			else {
				for (int i = curDepth; i < depth; i++) {
					frames.add(doAddStackFrame(i));
				}
				if (atInner) {
					int diff = depth - curDepth;
					shiftFrameAttributes(0, diff, curDepth, frames);
					clearFrameAttributes(0, diff, frames);
				}
			}
		}
	}

	protected TraceStackFrame doGetFrame(int level) {
		TraceObjectSchema schema = object.getSchema();
		PathFilter filter = schema.searchFor(TraceObjectStackFrame.class, true);
		PathFilter decFilter = filter.applyKeys(KeyPath.makeIndex(level));
		PathFilter hexFilter = filter.applyKeys("0x" + Integer.toHexString(level));
		Lifespan span = computeSpan();
		return object.getSuccessors(span, decFilter)
				.findAny()
				.map(p -> p.getDestination(object).queryInterface(TraceObjectStackFrame.class))
				.or(() -> object.getSuccessors(span, hexFilter)
						.findAny()
						.map(p -> p.getDestination(object)
								.queryInterface(TraceObjectStackFrame.class)))
				.orElse(null);
	}

	@Override
	// This assumes the frame indices are contiguous and include 0
	public TraceStackFrame getFrame(int level, boolean ensureDepth) {
		if (ensureDepth) {
			try (LockHold hold = object.getTrace().lockWrite()) {
				if (level >= getDepth()) {
					setDepth(level + 1, false);
				}
				return doGetFrame(level);
			}
		}
		try (LockHold hold = object.getTrace().lockRead()) {
			return doGetFrame(level);
		}
	}

	protected Stream<TraceObjectStackFrame> doGetFrames(long snap) {
		return object.querySuccessorsInterface(Lifespan.at(snap), TraceObjectStackFrame.class, true)
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
			object.removeTree(computeSpan());
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

	@Override
	public boolean hasFixedFrames() {
		return false;
	}
}
