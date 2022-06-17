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

import com.google.common.collect.Range;

import ghidra.dbg.target.TargetStackFrame;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.*;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectInterface;
import ghidra.trace.model.Trace.TraceStackChangeType;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceChangeType;
import ghidra.util.LockHold;

public class DBTraceObjectStack implements TraceObjectStack, DBTraceObjectInterface {

	protected class StackChangeTranslator extends Translator<TraceStack> {
		protected StackChangeTranslator(DBTraceObject object, TraceStack iface) {
			super(null, object, iface);
		}

		@Override
		protected TraceChangeType<TraceStack, Void> getAddedType() {
			return TraceStackChangeType.ADDED;
		}

		@Override
		protected TraceChangeType<TraceStack, Range<Long>> getLifespanChangedType() {
			return null;
		}

		@Override
		protected TraceChangeType<TraceStack, ?> getChangedType() {
			return TraceStackChangeType.CHANGED;
		}

		@Override
		protected boolean appliesToKey(String key) {
			return false;
		}

		@Override
		protected TraceChangeType<TraceStack, Void> getDeletedType() {
			return TraceStackChangeType.DELETED;
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
			return object
					.querySuccessorsInterface(computeSpan(), TraceObjectStackFrame.class)
					.map(f -> f.getLevel())
					.reduce(Integer::max)
					.map(m -> m + 1)
					.orElse(0);
		}
	}

	protected TraceObjectStackFrame doAddStackFrame(int level) {
		try (LockHold hold = object.getTrace().lockWrite()) {
			PathMatcher matcher = object.getTargetSchema().searchFor(TargetStackFrame.class, true);
			List<String> relKeyList =
				matcher.applyKeys(PathUtils.makeIndex(level)).getSingletonPath();
			if (relKeyList == null) {
				throw new IllegalStateException("Could not determine where to create new frame");
			}
			List<String> keyList =
				PathUtils.extend(object.getCanonicalPath().getKeyList(), relKeyList);
			return object.getManager().addStackFrame(keyList, getSnap());
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
		TargetObjectSchema schema = object.getTargetSchema();
		PathPredicates matcher = schema.searchFor(TargetStackFrame.class, true);
		PathPredicates decMatcher = matcher.applyKeys(PathUtils.makeIndex(level));
		PathPredicates hexMatcher = matcher.applyKeys("0x" + Integer.toHexString(level));
		Range<Long> span = computeSpan();
		return object.getSuccessors(span, decMatcher)
				.findAny()
				.map(p -> p.getDestination(object).queryInterface(TraceObjectStackFrame.class))
				.or(() -> object.getSuccessors(span, hexMatcher)
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
		else {
			try (LockHold hold = object.getTrace().lockRead()) {
				return doGetFrame(level);
			}
		}
	}

	protected Stream<TraceObjectStackFrame> doGetFrames(long snap) {
		return object
				.querySuccessorsInterface(Range.singleton(snap), TraceObjectStackFrame.class)
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
