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

import java.util.List;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface Step extends Comparable<Step> {
	enum StepType {
		TICK,
		SKIP,
		PATCH,
	}

	/**
	 * Parse a step, possibly including a thread prefix, e.g., {@code "t1-..."}
	 * 
	 * <p>
	 * If the thread prefix is given, the step applies to the given thread. Otherwise, the step
	 * applies to the last thread or the event thread.
	 * 
	 * @param stepSpec the string specification
	 * @return the parsed step
	 * @throws IllegalArgumentException if the specification is of the wrong form
	 */
	static Step parse(String stepSpec) {
		if ("".equals(stepSpec)) {
			return nop();
		}
		String[] parts = stepSpec.split("-");
		if (parts.length == 1) {
			return parse(-1, parts[0].trim());
		}
		if (parts.length == 2) {
			String tPart = parts[0].trim();
			if (tPart.startsWith("t")) {
				return parse(Long.parseLong(tPart.substring(1)), parts[1].trim());
			}
		}
		throw new IllegalArgumentException("Cannot parse step: '" + stepSpec + "'");
	}

	/**
	 * Parse a step for the given thread key
	 * 
	 * <p>
	 * The form of the spec must either be numeric, indicating some number of ticks, or
	 * brace-enclosed Sleigh code, e.g., {@code "{r0=0x1234}"}. The latter allows patching machine
	 * state during execution.
	 * 
	 * @param threadKey the thread to step, or -1 for the last thread or event thread
	 * @param stepSpec the string specification
	 * @return the parsed step
	 * @throws IllegalArgumentException if the specification is of the wrong form
	 */
	static Step parse(long threadKey, String stepSpec) {
		if (stepSpec.startsWith("s")) {
			return SkipStep.parse(threadKey, stepSpec);
		}
		if (stepSpec.startsWith("{")) {
			return PatchStep.parse(threadKey, stepSpec);
		}
		return TickStep.parse(threadKey, stepSpec);
	}

	static TickStep nop() {
		return new TickStep(-1, 0);
	}

	StepType getType();

	default int getTypeOrder() {
		return getType().ordinal();
	}

	boolean isNop();

	long getThreadKey();

	default boolean isEventThread() {
		return getThreadKey() == -1;
	}

	default TraceThread getThread(TraceThreadManager tm, TraceThread eventThread) {
		TraceThread thread = isEventThread() ? eventThread : tm.getThread(getThreadKey());
		if (thread == null) {
			if (isEventThread()) {
				throw new IllegalArgumentException("Thread must be given, e.g., 0:t1-3, " +
					"since the last thread or snapshot event thread is not given.");
			}
			throw new IllegalArgumentException(
				"Thread with key " + getThreadKey() + " does not exist in given trace");
		}
		return thread;
	}

	long getTickCount();

	long getPatchCount();

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
	boolean isCompatible(Step step);

	void addTo(Step step);

	Step subtract(Step step);

	Step clone();

	/**
	 * Subtract from the count of this step
	 * 
	 * <p>
	 * If this step has a count exceeding that given, then this method simply subtracts the given
	 * number from the {@code tickCount} and returns the (negative) difference. If this step has
	 * exactly the count given, this method sets the count to 0 and returns 0, indicating this step
	 * should be removed from the sequence. If the given count exceeds that of this step, this
	 * method sets the count to 0 and returns the (positive) difference, indicating this step should
	 * be removed from the sequence, and the remaining steps rewound from the preceding step.
	 * 
	 * @param steps the count to rewind
	 * @return the number of steps remaining
	 */
	long rewind(long count);

	/**
	 * Richly compare this step to another
	 * 
	 * @param step the object of comparison (this being the subject)
	 * @return a result describing the relationship from subject to object
	 */
	CompareResult compareStep(Step that);

	default CompareResult compareStepType(Step that) {
		return CompareResult
				.unrelated(Integer.compare(this.getTypeOrder(), that.getTypeOrder()));
	}

	@Override
	default int compareTo(Step that) {
		return compareStep(that).compareTo;
	}

	default TraceThread execute(TraceThreadManager tm, TraceThread eventThread,
			PcodeMachine<?> machine, Stepper stepper, TaskMonitor monitor)
			throws CancelledException {
		TraceThread thread = getThread(tm, eventThread);
		if (machine == null) {
			// Just performing validation (specifically thread parts)
			return thread;
		}
		PcodeThread<?> emuThread = machine.getThread(thread.getPath(), true);
		execute(emuThread, stepper, monitor);
		return thread;
	}

	<T> void execute(PcodeThread<T> emuThread, Stepper stepper, TaskMonitor monitor)
			throws CancelledException;

	long coalescePatches(Language language, List<Step> steps);
}
