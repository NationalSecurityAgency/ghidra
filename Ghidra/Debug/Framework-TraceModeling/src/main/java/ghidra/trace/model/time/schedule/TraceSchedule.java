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
package ghidra.trace.model.time.schedule;

import java.util.*;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class TraceSchedule implements Comparable<TraceSchedule> {
	public static final TraceSchedule ZERO = TraceSchedule.snap(0);

	public static final TraceSchedule snap(long snap) {
		return new TraceSchedule(snap, new Sequence(), new Sequence());
	}

	private static final String PARSE_ERR_MSG =
		"Time specification must have form 'snap[:steps[.pSteps]]'";

	/**
	 * Parse schedule in the form "{@code snap[:steps[.pSteps]]}"
	 * 
	 * <p>
	 * A schedule consists of a snap, a optional {@link Sequence} of thread instruction-level steps,
	 * and optional p-code-level steps (pSteps). The form of {@code steps} and {@code pSteps} is
	 * specified by {@link Sequence#parse(String)}. Each sequence consists of stepping selected
	 * threads forward, and/or patching machine state.
	 * 
	 * @param spec the string specification
	 * @return the parsed schedule
	 */
	public static TraceSchedule parse(String spec) {
		String[] parts = spec.split(":", 2);
		if (parts.length > 2) {
			throw new AssertionError();
		}
		final long snap;
		final Sequence ticks;
		final Sequence pTicks;
		try {
			snap = Long.decode(parts[0]);
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(PARSE_ERR_MSG, e);
		}
		if (parts.length > 1) {
			String[] subs = parts[1].split("\\.");
			try {
				ticks = Sequence.parse(subs[0]);
			}
			catch (IllegalArgumentException e) {
				throw new IllegalArgumentException(PARSE_ERR_MSG, e);
			}
			if (subs.length == 1) {
				pTicks = new Sequence();
			}
			else if (subs.length == 2) {
				try {
					pTicks = Sequence.parse(subs[1]);
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
			ticks = new Sequence();
			pTicks = new Sequence();
		}
		return new TraceSchedule(snap, ticks, pTicks);
	}

	private final long snap;
	private final Sequence steps;
	private final Sequence pSteps;

	/**
	 * Construct the given schedule
	 * 
	 * @param snap the initial trace snapshot
	 * @param steps the step sequence
	 * @param pSteps the of p-code step sequence
	 */
	public TraceSchedule(long snap, Sequence steps, Sequence pSteps) {
		this.snap = snap;
		this.steps = steps;
		this.pSteps = pSteps;
	}

	@Override
	public String toString() {
		if (pSteps.isNop()) {
			if (steps.isNop()) {
				return Long.toString(snap);
			}
			return String.format("%d:%s", snap, steps);
		}
		return String.format("%d:%s.%s", snap, steps, pSteps);
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

		result = this.steps.compareSeq(that.steps);
		switch (result) {
			case UNREL_LT:
			case UNREL_GT:
				return result;
			case REL_LT:
				if (this.pSteps.isNop()) {
					return CompareResult.REL_LT;
				}
				else {
					return CompareResult.UNREL_LT;
				}
			case REL_GT:
				if (that.pSteps.isNop()) {
					return CompareResult.REL_GT;
				}
				else {
					return CompareResult.UNREL_GT;
				}
			default: // EQUALS, compare pSteps
		}

		result = this.pSteps.compareSeq(that.pSteps);
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
		if (!Objects.equals(this.steps, that.steps)) {
			return false;
		}
		if (!Objects.equals(this.pSteps, that.pSteps)) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		return Objects.hash(snap, steps, pSteps);
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
		return steps.isNop() && pSteps.isNop();
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
		long last = pSteps.getLastThreadKey();
		if (last != -1) {
			return last;
		}
		return steps.getLastThreadKey();
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
	 * be passed to {@link #execute(Trace, PcodeMachine, TaskMonitor)} or similar. Note that patch
	 * steps do not count as ticks.
	 * 
	 * @return the number of ticks
	 */
	public long totalTickCount() {
		return steps.totalTickCount() + pSteps.totalTickCount();
	}

	/**
	 * Compute the total number of patches applied
	 * 
	 * @return the number of patches
	 */
	public long totalPatchCount() {
		return steps.totalPatchCount() + pSteps.totalPatchCount();
	}

	/**
	 * Compute the number of ticks taken, excluding p-code ticks
	 * 
	 * @return the number of ticks
	 */
	public long tickCount() {
		return steps.totalTickCount();
	}

	/**
	 * Compute the number of patches, excluding p-code patches
	 * 
	 * @return the number of patches
	 */
	public long patchCount() {
		return steps.totalPatchCount();
	}

	/**
	 * Compute the number of p-code ticks taken
	 * 
	 * @return the number of ticks
	 */
	public long pTickCount() {
		return pSteps.totalTickCount();
	}

	/**
	 * Compute the number of p-code patches applied
	 * 
	 * @return the number of patches
	 */
	public long pPatchCount() {
		return pSteps.totalPatchCount();
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
			steps.execute(trace, lastThread, machine, Stepper.instruction(), monitor);
		lastThread =
			pSteps.execute(trace, lastThread, machine, Stepper.pcode(), monitor);
	}

	/**
	 * Validate this schedule for the given trace
	 * 
	 * <p>
	 * This performs a dry run of the sequence on the given trace. If the schedule starts on the
	 * "last thread," it verifies the snapshot gives the event thread. It also checks that every
	 * thread key in the sequence exists in the trace.
	 * 
	 * @param trace the trace against which to validate this schedule
	 */
	public void validate(Trace trace) {
		TraceThread lastThread = getEventThread(trace);
		lastThread = steps.validate(trace, lastThread);
		lastThread = pSteps.validate(trace, lastThread);
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
		Sequence remains = steps.relativize(position.steps);
		if (remains.isNop()) {
			Sequence pRemains = this.pSteps.relativize(position.pSteps);
			lastThread =
				pRemains.execute(trace, lastThread, machine, Stepper.pcode(), monitor);
		}
		else {
			lastThread =
				remains.execute(trace, lastThread, machine, Stepper.instruction(), monitor);
			lastThread =
				pSteps.execute(trace, lastThread, machine, Stepper.pcode(), monitor);
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
	 * @param thread the thread to step, or null for the "last thread"
	 * @param tickCount the number of ticks to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule steppedForward(TraceThread thread, long tickCount) {
		Sequence steps = this.steps.clone();
		steps.advance(new TickStep(thread == null ? -1 : thread.getKey(), tickCount));
		return new TraceSchedule(snap, steps, new Sequence());
	}

	/**
	 * Behaves as in {@link #steppedForward(TraceThread, long)}, but by appending skips
	 * 
	 * @param thread the thread to step, or null for the "last thread"
	 * @param tickCount the number of skips to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule skippedForward(TraceThread thread, long tickCount) {
		Sequence steps = this.steps.clone();
		steps.advance(new SkipStep(thread == null ? -1 : thread.getKey(), tickCount));
		return new TraceSchedule(snap, steps, new Sequence());
	}

	protected TraceSchedule doSteppedBackward(Trace trace, long tickCount, Set<Long> visited) {
		if (!visited.add(snap)) {
			return null;
		}
		long excess = tickCount - totalTickCount() - totalPatchCount();
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
		Sequence steps = this.steps.clone();
		steps.rewind(tickCount);
		return new TraceSchedule(snap, steps, new Sequence());
	}

	/**
	 * Returns the equivalent of executing count instructions (and all p-code operations) less than
	 * this schedule
	 * 
	 * <p>
	 * This schedule is left unmodified. If it had any p-code steps, those steps and subsequent
	 * patches are dropped in the resulting schedule. If count exceeds this schedule's steps, it
	 * will try (recursively) to step the source snapshot's schedule backward, if known. Both ticks
	 * and patches counts as steps.
	 * 
	 * @param trace the trace of this schedule, for context
	 * @param stepCount the number of steps to take backward
	 * @return the resulting schedule or null if it cannot be computed
	 */
	public TraceSchedule steppedBackward(Trace trace, long stepCount) {
		return doSteppedBackward(trace, stepCount, new HashSet<>());
	}

	/**
	 * Returns the equivalent of executing the schedule followed by stepping the given thread
	 * {@code pTickCount} more p-code operations
	 * 
	 * @param thread the thread to step, or null for the "last thread"
	 * @param pTickCount the number of p-code ticks to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule steppedPcodeForward(TraceThread thread, int pTickCount) {
		Sequence pTicks = this.pSteps.clone();
		pTicks.advance(new TickStep(thread == null ? -1 : thread.getKey(), pTickCount));
		return new TraceSchedule(snap, steps.clone(), pTicks);
	}

	/**
	 * Behaves as in {@link #steppedPcodeForward(TraceThread, int)}, but by appending skips
	 * 
	 * @param thread the thread to step, or null for the "last thread"
	 * @param pTickCount the number of p-code skips to take the thread forward
	 * @return the resulting schedule
	 */
	public TraceSchedule skippedPcodeForward(TraceThread thread, int pTickCount) {
		Sequence pTicks = this.pSteps.clone();
		pTicks.advance(new SkipStep(thread == null ? -1 : thread.getKey(), pTickCount));
		return new TraceSchedule(snap, steps.clone(), pTicks);
	}

	/**
	 * Returns the equivalent of executing count p-code operations less than this schedule
	 * 
	 * <p>
	 * If {@code pStepCount} exceeds the p-code steps of this schedule, null is returned, since we
	 * cannot know <em>a priori</em> how many p-code steps would be required to complete the
	 * preceding instruction step. Both p-code ticks and p-code patches counts as p-code steps.
	 * 
	 * @param pStepCount the number of p-code steps to take backward
	 * @return the resulting schedule or null if it cannot be computed
	 */
	public TraceSchedule steppedPcodeBackward(int pStepCount) {
		if (pStepCount > pSteps.totalTickCount()) {
			return null;
		}
		Sequence pTicks = this.pSteps.clone();
		pTicks.rewind(pStepCount);
		return new TraceSchedule(snap, steps.clone(), pTicks);
	}

	private long keyOf(TraceThread thread) {
		return thread == null ? -1 : thread.getKey();
	}

	/**
	 * Returns the equivalent of executing this schedule then performing a given patch
	 * 
	 * @param thread the thread context for the patch; cannot be null
	 * @param sleigh a single line of sleigh, excluding the terminating semicolon.
	 * @return the resulting schedule
	 */
	public TraceSchedule patched(TraceThread thread, String sleigh) {
		if (!this.pSteps.isNop()) {
			Sequence pTicks = this.pSteps.clone();
			pTicks.advance(new PatchStep(thread.getKey(), sleigh));
			pTicks.coalescePatches(thread.getTrace().getBaseLanguage());
			return new TraceSchedule(snap, steps.clone(), pTicks);
		}
		Sequence ticks = this.steps.clone();
		ticks.advance(new PatchStep(keyOf(thread), sleigh));
		ticks.coalescePatches(thread.getTrace().getBaseLanguage());
		return new TraceSchedule(snap, ticks, new Sequence());
	}

	/**
	 * Returns the equivalent of executing this schedule then performing the given patches
	 * 
	 * @param thread the thread context for the patch; cannot be null
	 * @param sleigh the lines of sleigh, excluding the terminating semicolons.
	 * @return the resulting schedule
	 */
	public TraceSchedule patched(TraceThread thread, List<String> sleigh) {
		if (!this.pSteps.isNop()) {
			Sequence pTicks = this.pSteps.clone();
			for (String line : sleigh) {
				pTicks.advance(new PatchStep(thread.getKey(), line));
			}
			pTicks.coalescePatches(thread.getTrace().getBaseLanguage());
			return new TraceSchedule(snap, steps.clone(), pTicks);
		}
		Sequence ticks = this.steps.clone();
		for (String line : sleigh) {
			ticks.advance(new PatchStep(thread.getKey(), line));
		}
		ticks.coalescePatches(thread.getTrace().getBaseLanguage());
		return new TraceSchedule(snap, ticks, new Sequence());
	}
}
