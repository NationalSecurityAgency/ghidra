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
package ghidra.trace.model.time;

import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TraceSchedule implements Comparable<TraceSchedule> {
	public static final TraceSchedule ZERO = TraceSchedule.snap(0);

	public static final TraceSchedule snap(long snap) {
		return new TraceSchedule(snap, new TickSequence(), new TickSequence());
	}

	/**
	 * The result of a rich comparison of two schedules (or parts thereof)
	 */
	public enum CompareResult {
		UNREL_LT(-1, false),
		REL_LT(-1, true),
		EQUALS(0, true),
		REL_GT(1, true),
		UNREL_GT(1, false);

		/**
		 * Enrich the result of {@link Comparable#compareTo(Object)}, given that the two are related
		 * 
		 * @param compareTo the return from {@code compareTo}
		 * @return the rich result
		 */
		public static CompareResult related(int compareTo) {
			if (compareTo < 0) {
				return REL_LT;
			}
			if (compareTo > 0) {
				return REL_GT;
			}
			return EQUALS;
		}

		/**
		 * Enrich the result of {@link Comparable#compareTo(Object)}, given that the two are not
		 * related
		 * 
		 * @param compareTo the return from {@code compareTo}
		 * @return the rich result
		 */
		public static CompareResult unrelated(int compareTo) {
			if (compareTo < 0) {
				return UNREL_LT;
			}
			if (compareTo > 0) {
				return UNREL_GT;
			}
			return EQUALS;
		}

		/**
		 * Maintain sort order, but specify the two are not in fact related
		 * 
		 * @param result the result of another (usually recursive) rich comparison
		 * @return the modified result
		 */
		public static CompareResult unrelated(CompareResult result) {
			return unrelated(result.compareTo);
		}

		public final int compareTo;
		public final boolean related;

		CompareResult(int compareTo, boolean related) {
			this.compareTo = compareTo;
			this.related = related;
		}
	}

	/**
	 * A step of a given thread in a schedule, repeated some number of times
	 */
	public static class TickStep implements Comparable<TickStep> {

		/**
		 * Parse a step of the form "{@code 3}" or {@code "t1-3"}
		 * 
		 * <p>
		 * The first form steps the last thread the given number of times, e.g., 3. The second form
		 * steps the given thread, e.g., 1, the given number of times.
		 * 
		 * @param stepSpec the string specification
		 * @return the parsed step
		 * @throws IllegalArgumentException if the specification is of the wrong form
		 */
		public static TickStep parse(String stepSpec) {
			if ("".equals(stepSpec)) {
				return new TickStep(-1, 0);
			}
			String[] parts = stepSpec.split("-");
			if (parts.length == 1) {
				return new TickStep(-1, Long.parseLong(parts[0].trim()));
			}
			if (parts.length == 2) {
				String tPart = parts[0].trim();
				if (tPart.startsWith("t")) {
					return new TickStep(Long.parseLong(tPart.substring(1)),
						Long.parseLong(parts[1].trim()));
				}
			}
			throw new IllegalArgumentException("Cannot parse step: '" + stepSpec + "'");
		}

		protected final long threadKey;
		protected long tickCount;

		/**
		 * Construct a step for the given thread with the given tick count
		 * 
		 * @param threadKey the key of the thread in the trace, -1 for the "last thread"
		 * @param tickCount the number of times to step the thread
		 */
		public TickStep(long threadKey, long tickCount) {
			if (tickCount < 0) {
				throw new IllegalArgumentException("Cannot step a negative number");
			}
			this.threadKey = threadKey;
			this.tickCount = tickCount;
		}

		@Override
		public String toString() {
			if (threadKey == -1) {
				return Long.toString(tickCount);
			}
			return String.format("t%d-%d", threadKey, tickCount);
		}

		@Override
		public TickStep clone() {
			return new TickStep(threadKey, tickCount);
		}

		/**
		 * Add to the count of this step
		 * 
		 * @param steps the count to add
		 */
		public void advance(long steps) {
			if (steps < 0) {
				throw new IllegalArgumentException("Cannot advance a negative number");
			}
			long newCount = tickCount + steps;
			if (newCount < 0) {
				throw new IllegalArgumentException("Total step count exceeds LONG_MAX");
			}
			this.tickCount = newCount;
		}

		/**
		 * Subtract from the count of this step
		 * 
		 * <p>
		 * If this step has a count exceeding that given, then this method simply subtracts the
		 * given number from the {@code tickCount} and returns the (negative) difference. If this
		 * step has exactly the count given, this method sets the count to 0 and returns 0,
		 * indicating this step should be removed from the sequence. If the given count exceeds that
		 * of this step, this method sets the count to 0 and returns the (positive) difference,
		 * indicating this step should be removed from the sequence, and the remaining steps rewound
		 * from the preceding step.
		 * 
		 * @param steps the count to rewind
		 * @return the number of steps remaining
		 */
		public long rewind(long steps) {
			if (steps < 0) {
				throw new IllegalArgumentException("Cannot rewind a negative number");
			}
			long diff = this.tickCount - steps;
			this.tickCount = Long.max(0, diff);
			return -diff;
		}

		/**
		 * Check if the given step can be combined with this one
		 * 
		 * <p>
		 * Two steps applied to the same thread can just be summed. If the given step applies to the
		 * "last thread" or to the same thread as this step, then it can be combined.
		 * 
		 * @param step the second step
		 * @return true if combinable, false otherwise.
		 */
		public boolean canCombine(TickStep step) {
			return this.threadKey == step.threadKey || step.threadKey == -1;
		}

		@Override
		public int hashCode() {
			return Long.hashCode(threadKey) * 31 + Long.hashCode(tickCount);
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof TickStep)) {
				return false;
			}
			TickStep that = (TickStep) obj;
			if (this.threadKey != that.threadKey) {
				return false;
			}
			if (this.tickCount != that.tickCount) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(TickStep that) {
			return compareStep(that).compareTo;
		}

		/**
		 * Richly compare this step to another
		 * 
		 * @param that the object of comparison (this being the subject)
		 * @return a result describing the relationship from subject to object
		 */
		public CompareResult compareStep(TickStep that) {
			CompareResult result;

			result = CompareResult.unrelated(Long.compare(this.threadKey, that.threadKey));
			if (result != CompareResult.EQUALS) {
				return result;
			}

			result = CompareResult.related(Long.compare(this.tickCount, that.tickCount));
			if (result != CompareResult.EQUALS) {
				return result;
			}

			return CompareResult.EQUALS;
		}
	}

	/**
	 * A sequence of thread steps, each repeated some number of times
	 */
	public static class TickSequence implements Comparable<TickSequence> {

		/**
		 * Parse (and normalize) a sequence of steps
		 * 
		 * <p>
		 * This takes a comma-separated list of steps in the form specified by
		 * {@link TickStep#parse(String)}. Each step may or may not specify a thread, but it's
		 * uncommon for any but the first step to omit the thread. The sequence is normalized as it
		 * is parsed, so any step after the first that omits a thread will be combined with the
		 * previous step. When the first step applies to the "last thread," it typically means the
		 * "event thread" of the source trace snapshot.
		 * 
		 * @param seqSpec the string specification of the sequence
		 * @return the parsed sequence
		 * @throws IllegalArgumentException if the specification is of the wrong form
		 */
		public static TickSequence parse(String seqSpec) {
			TickSequence result = new TickSequence();
			for (String stepSpec : seqSpec.split(",")) {
				TickStep step = TickStep.parse(stepSpec);
				result.advance(step);
			}
			return result;
		}

		/**
		 * Construct (and normalize) a sequence of the specified steps
		 * 
		 * @param steps the desired steps in order
		 * @return the resulting sequence
		 */
		public static TickSequence of(TickStep... steps) {
			return of(Arrays.asList(steps));
		}

		/**
		 * Construct (and normalize) a sequence of the specified steps
		 * 
		 * @param steps the desired steps in order
		 * @return the resulting sequence
		 */
		public static TickSequence of(List<TickStep> steps) {
			TickSequence result = new TickSequence();
			for (TickStep step : steps) {
				result.advance(step);
			}
			return result;
		}

		/**
		 * Construct (and normalize) a sequence formed by the steps in a followed by the steps in b
		 * 
		 * @param a the first sequence
		 * @param b the second (appended) sequence
		 * @return the resulting sequence
		 */
		public static TickSequence catenate(TickSequence a, TickSequence b) {
			TickSequence result = new TickSequence();
			result.advance(a);
			result.advance(b);
			return result;
		}

		private final List<TickStep> steps;

		protected TickSequence() {
			this(new ArrayList<>());
		}

		protected TickSequence(List<TickStep> steps) {
			this.steps = steps;
		}

		@Override
		public String toString() {
			return StringUtils.join(steps, ',');
		}

		/**
		 * Append the given step to this sequence
		 * 
		 * @param step the step to append
		 */
		public void advance(TickStep step) {
			if (step.tickCount == 0) {
				return;
			}
			if (steps.isEmpty()) {
				steps.add(step);
				return;
			}
			TickStep last = steps.get(steps.size() - 1);
			if (!last.canCombine(step)) {
				steps.add(step.clone());
				return;
			}
			last.advance(step.tickCount);
		}

		/**
		 * Append the given sequence to this one
		 * 
		 * @param seq the sequence to append
		 */
		public void advance(TickSequence seq) {
			int size = seq.steps.size();
			// Clone early in case seq == this
			// I should store copies of subsequent steps, anyway
			List<TickStep> clone = seq.steps.stream()
					.map(TickStep::clone)
					.collect(Collectors.toList());
			if (size < 1) {
				return;
			}
			// intervening -1 could resolve and be combined with following
			advance(clone.get(0));
			if (size < 2) {
				return;
			}
			advance(clone.get(1));
			steps.addAll(clone.subList(2, size));
		}

		/**
		 * Rewind this sequence the given step count
		 * 
		 * <p>
		 * This modifies the sequence in place, removing the given count from the end of the
		 * sequence. Any step whose count is reduced to 0 as a result of rewinding is removed
		 * entirely from the sequence.
		 * 
		 * @param count the step count to rewind
		 * @return if count exceeds the steps of this sequence, the (positive) difference remaining
		 */
		public long rewind(long count) {
			if (count < 0) {
				throw new IllegalArgumentException("Cannot rewind a negative number");
			}
			while (!steps.isEmpty()) {
				int lastIndex = steps.size() - 1;
				count = steps.get(lastIndex).rewind(count);
				if (count >= 0) {
					steps.remove(lastIndex);
				}
				if (count <= 0) {
					break;
				}
			}
			return Long.max(0, count);
		}

		@Override
		public TickSequence clone() {
			return new TickSequence(
				steps.stream().map(TickStep::clone).collect(Collectors.toList()));
		}

		/**
		 * Obtain a clone of the steps
		 * 
		 * <p>
		 * Modifications to the returned steps have no effect on this sequence.
		 * 
		 * @return the cloned steps
		 */
		public List<TickStep> getSteps() {
			return steps.stream().map(TickStep::clone).collect(Collectors.toUnmodifiableList());
		}

		/**
		 * Check if this sequence represents any actions
		 * 
		 * @return true if the sequence is empty, false if not
		 */
		public boolean isNop() {
			return steps.isEmpty();
		}

		@Override
		public int hashCode() {
			return steps.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (!(obj instanceof TickSequence)) {
				return false;
			}
			TickSequence that = (TickSequence) obj;
			return Objects.equals(this.steps, that.steps);
		}

		/**
		 * Richly compare to sequences
		 * 
		 * <p>
		 * The result indicates not only which is "less" or "greater" than the other, but also
		 * indicates whether the two are "related." Two sequences are considered related if one is
		 * the prefix to the other. More precisely, they are related if it's possible to transform
		 * one into the other solely by truncation (rewind) or solely by concatenation (advance).
		 * When related, the prefix is considered "less than" the other. Equal sequences are
		 * trivially related.
		 * 
		 * <p>
		 * Examples:
		 * <ul>
		 * <li>{@code ""} is related to and less than {@code "10"}</li>
		 * <li>{@code "10"} is related and equal to {@code "10"}</li>
		 * <li>{@code "10"} is related to and less than {@code "11"}</li>
		 * <li>{@code "t1-5"} is related to and less than {@code "t1-5,t2-4"}</li>
		 * <li>{@code "t1-5"} is un-related to and less than {@code "t1-4,t2-4"}</li>
		 * </ul>
		 * 
		 * <p>
		 * The {@link #compareTo(TickSequence)} implementation defers to this method. Thus, in a
		 * sorted set of tick sequences, the floor of a given sequence is will be the longest prefix
		 * in that set to the given sequence, assuming such a prefix is present.
		 * 
		 * @param that the object of comparison (this being the subject)
		 * @return a result describing the relationship from subject to object
		 */
		public CompareResult compareSeq(TickSequence that) {
			int min = Math.min(this.steps.size(), that.steps.size());
			CompareResult result;
			for (int i = 0; i < min; i++) {
				TickStep s1 = this.steps.get(i);
				TickStep s2 = that.steps.get(i);
				result = s1.compareStep(s2);
				switch (result) {
					case UNREL_LT:
					case UNREL_GT:
						return result;
					case REL_LT:
						if (i + 1 == this.steps.size()) {
							return CompareResult.REL_LT;
						}
						else {
							return CompareResult.UNREL_LT;
						}
					case REL_GT:
						if (i + 1 == that.steps.size()) {
							return CompareResult.REL_GT;
						}
						else {
							return CompareResult.UNREL_GT;
						}
					default: // EQUALS, next step
				}
			}
			if (that.steps.size() > min) {
				return CompareResult.REL_LT;
			}
			if (this.steps.size() > min) {
				return CompareResult.REL_GT;
			}
			return CompareResult.EQUALS;
		}

		@Override
		public int compareTo(TickSequence that) {
			return compareSeq(that).compareTo;
		}

		/**
		 * Compute the sequence which concatenated to the given prefix would result in this sequence
		 * 
		 * <p>
		 * The returned tick sequence should not be manipulated, since it may just be this sequence.
		 * 
		 * @see #compareSeq(TickSequence)
		 * @param prefix the prefix
		 * @return the relative sequence from prefix to this
		 * @throws IllegalArgumentException if prefix is not a prefix of this sequence
		 */
		public TickSequence relativize(TickSequence prefix) {
			if (prefix.isNop()) {
				return this;
			}
			CompareResult comp = compareSeq(prefix);
			TickSequence result = new TickSequence();
			if (comp == CompareResult.EQUALS) {
				return result;
			}
			if (comp != CompareResult.REL_GT) {
				throw new IllegalArgumentException(String.format(
					"The given prefix (%s) is not actually a prefix of this (%s).", prefix, this));
			}

			int lastStepIndex = prefix.steps.size() - 1;
			TickStep ancestorLast = prefix.steps.get(lastStepIndex);
			TickStep continuation = this.steps.get(lastStepIndex);
			long toFinish = continuation.tickCount - ancestorLast.tickCount;
			if (toFinish > 0) {
				result.advance(new TickStep(ancestorLast.threadKey, toFinish));
			}
			result.steps.addAll(steps.subList(prefix.steps.size(), steps.size()));
			return result;
		}

		/**
		 * Compute to total number of steps specified
		 * 
		 * @return the total
		 */
		public long totalTickCount() {
			long count = 0;
			for (TickStep step : steps) {
				count += step.tickCount;
			}
			return count;
		}

		/**
		 * Execute this sequence upon the given machine
		 * 
		 * <p>
		 * Threads are retrieved from the database by key, then created in the machine (if not
		 * already present) named by {@link TraceThread#getPath()}. The caller should ensure the
		 * machine's state is bound to the given trace.
		 * 
		 * @param trace the trace to which the machine is bound
		 * @param eventThread the thread for the first step, if it applies to the "last thread"
		 * @param machine the machine to step
		 * @param action the action to step each thread
		 * @param monitor a monitor for cancellation and progress reports
		 * @return the last trace thread stepped during execution
		 * @throws CancelledException if execution is cancelled
		 */
		public TraceThread execute(Trace trace, TraceThread eventThread, PcodeMachine<?> machine,
				Consumer<PcodeThread<?>> action, TaskMonitor monitor) throws CancelledException {
			TraceThreadManager tm = trace.getThreadManager();
			TraceThread thread = eventThread;
			for (TickStep step : steps) {
				thread = step.threadKey == -1 ? eventThread : tm.getThread(step.threadKey);
				if (thread == null) {
					if (step.threadKey == -1) {
						throw new IllegalArgumentException(
							"Thread key -1 can only be used if last/event thread is given");
					}
					throw new IllegalArgumentException(
						"Thread with key " + step.threadKey + " does not exist in given trace");
				}

				PcodeThread<?> emuThread = machine.getThread(thread.getPath(), true);
				for (int i = 0; i < step.tickCount; i++) {
					monitor.incrementProgress(1);
					monitor.checkCanceled();
					action.accept(emuThread);
				}
			}
			return thread;
		}

		/**
		 * Get the key of the last thread stepped
		 * 
		 * @return the key, or -1 if no step in the sequence specifies a thread
		 */
		public long getLastThreadKey() {
			if (steps.isEmpty()) {
				return -1;
			}
			return steps.get(steps.size() - 1).threadKey;
		}
	}

	private static final String PARSE_ERR_MSG =
		"Time specification must have form 'snap[:ticks[.pTicks]]'";

	/**
	 * Parse schedule in the form "{@code snap[:ticks[.pTicks]]}"
	 * 
	 * <p>
	 * A schedule consists of a snap, a optional sequence of thread instruction-level steps (ticks),
	 * and optional p-code-level steps ({@code pTicks}). The form of {@code ticks} and
	 * {@code pTicks} is specified by {@link TickSequence#parse(String)}.
	 * 
	 * @param spec the string specification
	 * @return the parsed schedule
	 */
	public static TraceSchedule parse(String spec) {
		String[] parts = spec.split(":");
		if (parts.length > 2) {
			throw new IllegalArgumentException(PARSE_ERR_MSG);
		}
		final long snap;
		final TickSequence ticks;
		final TickSequence pTicks;
		try {
			snap = Long.decode(parts[0]);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(PARSE_ERR_MSG, e);
		}
		if (parts.length > 1) {
			String[] subs = parts[1].split("\\.");
			try {
				ticks = TickSequence.parse(subs[0]);
			}
			catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(PARSE_ERR_MSG, e);
			}
			if (subs.length == 1) {
				pTicks = new TickSequence();
			}
			else if (subs.length == 2) {
				try {
					pTicks = TickSequence.parse(subs[1]);
				}
				catch (IllegalArgumentException e) {
					throw new IllegalArgumentException(PARSE_ERR_MSG, e);
				}
			}
			else {
				throw new IllegalArgumentException(PARSE_ERR_MSG);
			}
		}
		else {
			ticks = new TickSequence();
			pTicks = new TickSequence();
		}
		return new TraceSchedule(snap, ticks, pTicks);
	}

	private final long snap;
	private final TickSequence ticks;
	private final TickSequence pTicks;

	/**
	 * Construct the given schedule
	 * 
	 * @param snap the initial trace snapshot
	 * @param ticks the tick sequence
	 * @param pTicks the of p-code tick sequence
	 */
	public TraceSchedule(long snap, TickSequence ticks, TickSequence pTicks) {
		this.snap = snap;
		this.ticks = ticks;
		this.pTicks = pTicks;
	}

	@Override
	public String toString() {
		if (pTicks.isNop()) {
			if (ticks.isNop()) {
				return Long.toString(snap);
			}
			return String.format("%d:%s", snap, ticks);
		}
		return String.format("%d:%s.%s", snap, ticks, pTicks);
	}

	/**
	 * Richly compare two schedules
	 * 
	 * <p>
	 * Schedules starting at different snapshots are never related, because there is no
	 * emulator/simulator stepping action which advances to the next snapshot. Though p-code steps
	 * may comprise a partial step, we do not consider a partial step to be a prefix of a full step,
	 * since we cannot know <em>a priori</em> how many p-code steps comprise a full instruction
	 * step. Consider, e.g., the user may specify 100 p-code steps, which could effect 20
	 * instruction steps.
	 * 
	 * @param that the object of comparison (this being the subject)
	 * @return a result describing the relationship from subject to object
	 */
	public CompareResult compareSchedule(TraceSchedule that) {
		CompareResult result;

		result = CompareResult.unrelated(Long.compare(this.snap, that.snap));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		result = this.ticks.compareSeq(that.ticks);
		switch (result) {
			case UNREL_LT:
			case UNREL_GT:
				return result;
			case REL_LT:
				if (this.pTicks.isNop()) {
					return CompareResult.REL_LT;
				}
				else {
					return CompareResult.UNREL_LT;
				}
			case REL_GT:
				if (that.pTicks.isNop()) {
					return CompareResult.REL_GT;
				}
				else {
					return CompareResult.UNREL_GT;
				}
			default: // EQUALS, compare pTicks
		}

		result = this.pTicks.compareSeq(that.pTicks);
		if (result != CompareResult.EQUALS) {
			return result;
		}

		return CompareResult.EQUALS;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof TraceSchedule)) {
			return false;
		}
		TraceSchedule that = (TraceSchedule) obj;
		if (this.snap != that.snap) {
			return false;
		}
		if (!Objects.equals(this.ticks, that.ticks)) {
			return false;
		}
		if (!Objects.equals(this.pTicks, that.pTicks)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(snap, ticks, pTicks);
	}

	@Override
	public int compareTo(TraceSchedule o) {
		return compareSchedule(o).compareTo;
	}

	/**
	 * Check if this schedule requires any stepping
	 * 
	 * @return true if no stepping is required, i.e., the resulting state can be realized simply by
	 *         loading a snapshot
	 */
	public boolean isSnapOnly() {
		return ticks.isNop() && pTicks.isNop();
	}

	/**
	 * Get the source snapshot
	 * 
	 * @return
	 */
	public long getSnap() {
		return snap;
	}

	/**
	 * Get the last thread key stepped by this schedule
	 * 
	 * @return
	 */
	public long getLastThreadKey() {
		long last = pTicks.getLastThreadKey();
		if (last != -1) {
			return last;
		}
		return ticks.getLastThreadKey();
	}

	/**
	 * Get the event thread for this schedule in the context of the given trace
	 * 
	 * <p>
	 * This is the thread stepped when no thread is specified for the first step of the sequence.
	 * 
	 * @param trace the trace containing the source snapshot and threads
	 * @return the thread to use as "last thread" for the sequence
	 */
	public TraceThread getEventThread(Trace trace) {
		TraceSnapshot snapshot = trace.getTimeManager().getSnapshot(snap, false);
		return snapshot == null ? null : snapshot.getEventThread();
	}

	/**
	 * Get the last thread stepped by this schedule in the context of the given trace
	 * 
	 * @param trace the trace containing the source snapshot and threads
	 * @return the thread last stepped, or the "event thread" when no steps are taken
	 */
	public TraceThread getLastThread(Trace trace) {
		long lastKey = getLastThreadKey();
		if (lastKey == -1) {
			return getEventThread(trace);
		}
		return trace.getThreadManager().getThread(lastKey);
	}

	/**
	 * Compute the total number of ticks taken, including the p-code ticks
	 * 
	 * <p>
	 * This is suitable for use with {@link TaskMonitor#initialize(long)}, where that monitor will
	 * be passed to {@link #execute(Trace, PcodeMachine, TaskMonitor)} or similar.
	 * 
	 * @return the number of ticks
	 */
	public long totalTickCount() {
		return ticks.totalTickCount() + pTicks.totalTickCount();
	}

	/**
	 * Compute the number of ticks taken, excluding p-code ticks
	 * 
	 * @return the number of ticks
	 */
	public long tickCount() {
		return ticks.totalTickCount();
	}

	/**
	 * Compute the number of p-code ticks taken
	 * 
	 * @return the number of ticks
	 */
	public long pTickCount() {
		return pTicks.totalTickCount();
	}

	/**
	 * Realize the machine state for this schedule using the given trace and machine
	 * 
	 * <p>
	 * This method executes this schedule and trailing p-code steps on the given machine, assuming
	 * that machine is already "positioned" at the initial snapshot. Assuming successful execution,
	 * that machine is now said to be "positioned" at this schedule, and its state is the result of
	 * said execution.
	 * 
	 * @param trace the trace containing the source snapshot and threads
	 * @param machine a machine bound to the trace whose current state reflects the initial snapshot
	 * @param monitor a monitor for cancellation and progress reporting
	 * @throws CancelledException if the execution is cancelled
	 */
	public void execute(Trace trace, PcodeMachine<?> machine, TaskMonitor monitor)
			throws CancelledException {
		TraceThread lastThread = getEventThread(trace);
		lastThread =
			ticks.execute(trace, lastThread, machine, PcodeThread::stepInstruction, monitor);
		lastThread =
			pTicks.execute(trace, lastThread, machine, PcodeThread::stepPcodeOp, monitor);
	}

	/**
	 * Realize the machine state for this schedule using the given trace and pre-positioned machine
	 * 
	 * <p>
	 * This method executes the remaining steps of this schedule and trailing p-code steps on the
	 * given machine, assuming that machine is already "positioned" at another given schedule.
	 * Assuming successful execution, that machine is now said to be "positioned" at this schedule,
	 * and its state is the result of said execution.
	 * 
	 * @param trace the trace containing the source snapshot and threads
	 * @param position the current schedule of the given machine
	 * @param machine a machine bound to the trace whose current state reflects the given position
	 * @param monitor a monitor for cancellation and progress reporting
	 * @throws CancelledException if the execution is cancelled
	 * @throws IllegalArgumentException if the given position is not a prefix of this schedule
	 */
	public void finish(Trace trace, TraceSchedule position, PcodeMachine<?> machine,
			TaskMonitor monitor) throws CancelledException {
		TraceThread lastThread = position.getLastThread(trace);
		TickSequence remains = ticks.relativize(position.ticks);
		if (remains.isNop()) {
			TickSequence pRemains = this.pTicks.relativize(position.pTicks);
			lastThread =
				pRemains.execute(trace, lastThread, machine, PcodeThread::stepPcodeOp, monitor);
		}
		else {
			lastThread =
				remains.execute(trace, lastThread, machine, PcodeThread::stepInstruction, monitor);
			lastThread =
				pTicks.execute(trace, lastThread, machine, PcodeThread::stepPcodeOp, monitor);
		}
	}

	/**
	 * Returns the equivalent of executing the schedule (ignoring p-code steps) followed by stepping
	 * the given thread count more instructions
	 * 
	 * <p>
	 * This schedule is left unmodified. If it had any p-code steps, those steps are dropped in the
	 * resulting schedule.
	 * 
	 * @param thread the thread to step
	 * @param tickCount the number of ticks to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule steppedForward(TraceThread thread, long tickCount) {
		TickSequence ticks = this.ticks.clone();
		ticks.advance(new TickStep(thread.getKey(), tickCount));
		return new TraceSchedule(snap, ticks, new TickSequence());
	}

	protected TraceSchedule doSteppedBackward(Trace trace, long tickCount, Set<Long> visited) {
		if (!visited.add(snap)) {
			return null;
		}
		long excess = tickCount - totalTickCount();
		if (excess > 0) {
			if (trace == null) {
				return null;
			}
			TraceSnapshot source = trace.getTimeManager().getSnapshot(snap, false);
			if (source == null) {
				return null;
			}
			TraceSchedule rec = source.getSchedule();
			if (rec == null) {
				return null;
			}
			return rec.doSteppedBackward(trace, excess, visited);
		}
		TickSequence ticks = this.ticks.clone();
		ticks.rewind(tickCount);
		return new TraceSchedule(snap, ticks, new TickSequence());
	}

	/**
	 * Returns the equivalent of executing count instructions (and all p-code operations) less than
	 * this schedule
	 * 
	 * <p>
	 * This schedule is left unmodified. If it had any p-code steps, those steps are dropped in the
	 * resulting schedule. If count exceeds this schedule's steps, it will try (recursively) to step
	 * the source snapshot's schedule backward, if known.
	 * 
	 * @param trace the trace of this schedule, for context
	 * @param tickCount the number of ticks to take backward
	 * @return the resulting schedule or null if it cannot be computed
	 */
	public TraceSchedule steppedBackward(Trace trace, long tickCount) {
		return doSteppedBackward(trace, tickCount, new HashSet<>());
	}

	/**
	 * Returns the equivalent of executing the schedule followed by stepping the given thread
	 * {@code pTickCount} more p-code operations
	 * 
	 * @param thread the thread to step
	 * @param pTickCount the number of p-code ticks to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule steppedPcodeForward(TraceThread thread, int pTickCount) {
		TickSequence pTicks = this.pTicks.clone();
		pTicks.advance(new TickStep(thread.getKey(), pTickCount));
		return new TraceSchedule(snap, ticks, pTicks);
	}

	/**
	 * Returns the equivalent of executing count p-code operations less than this schedule
	 * 
	 * <p>
	 * If {@code pTickCount} exceeds the p-code ticks of this schedule, null is returned, since we
	 * cannot know <em>a priori</em> how many p-code steps would be required to complete the
	 * preceding instruction step.
	 * 
	 * @param pTickCount the number of p-code ticks to take backward
	 * @return the resulting schedule or null if it cannot be computed
	 */
	public TraceSchedule steppedPcodeBackward(int pTickCount) {
		if (pTickCount > pTicks.totalTickCount()) {
			return null;
		}
		TickSequence pTicks = this.pTicks.clone();
		pTicks.rewind(pTickCount);
		return new TraceSchedule(snap, ticks, pTicks);
	}
}
