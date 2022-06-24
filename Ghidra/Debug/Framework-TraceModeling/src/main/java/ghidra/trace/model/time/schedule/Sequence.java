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
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A sequence of thread steps, each repeated some number of times
 */
public class Sequence implements Comparable<Sequence> {
	public static final String SEP = ";";

	/**
	 * Parse (and normalize) a sequence of steps
	 * 
	 * <p>
	 * This takes a semicolon-separated list of steps in the form specified by
	 * {@link Step#parse(String)}. Each step may or may not specify a thread, but it's uncommon for
	 * any but the first step to omit the thread. The sequence is normalized as it is parsed, so any
	 * step after the first that omits a thread will be combined with the previous step. When the
	 * first step applies to the "last thread," it typically means the "event thread" of the source
	 * trace snapshot.
	 * 
	 * @param seqSpec the string specification of the sequence
	 * @return the parsed sequence
	 * @throws IllegalArgumentException if the specification is of the wrong form
	 */
	public static Sequence parse(String seqSpec) {
		Sequence result = new Sequence();
		for (String stepSpec : seqSpec.split(SEP)) {
			Step step = Step.parse(stepSpec);
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
	public static Sequence of(Step... steps) {
		return of(Arrays.asList(steps));
	}

	/**
	 * Construct (and normalize) a sequence of the specified steps
	 * 
	 * @param steps the desired steps in order
	 * @return the resulting sequence
	 */
	public static Sequence of(List<? extends Step> steps) {
		Sequence result = new Sequence();
		for (Step step : steps) {
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
	public static Sequence catenate(Sequence a, Sequence b) {
		Sequence result = new Sequence();
		result.advance(a);
		result.advance(b);
		return result;
	}

	private final List<Step> steps;

	protected Sequence() {
		this(new ArrayList<>());
	}

	protected Sequence(List<Step> steps) {
		this.steps = steps;
	}

	@Override
	public String toString() {
		return StringUtils.join(steps, SEP);
	}

	/**
	 * Append the given step to this sequence
	 * 
	 * @param step the step to append
	 */
	public void advance(Step step) {
		if (step.isNop()) {
			return;
		}
		if (steps.isEmpty()) {
			steps.add(step.clone());
			return;
		}
		Step last = steps.get(steps.size() - 1);
		if (!last.isCompatible(step)) {
			steps.add(step.clone());
			return;
		}
		last.addTo(step);
	}

	/**
	 * Append the given sequence to this one
	 * 
	 * @param seq the sequence to append
	 */
	public void advance(Sequence seq) {
		int size = seq.steps.size();
		// Clone early in case seq == this
		// I should store copies of subsequent steps, anyway
		List<Step> clone = seq.steps.stream()
				.map(Step::clone)
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

	public void coalescePatches(Language language) {
		if (steps.isEmpty()) {
			return;
		}
		Step last = steps.get(steps.size() - 1);
		long toRemove = last.coalescePatches(language, steps);
		for (; toRemove > 0; toRemove--) {
			steps.remove(steps.size() - 1);
		}
	}

	/**
	 * Rewind this sequence the given step count
	 * 
	 * <p>
	 * This modifies the sequence in place, removing the given count from the end of the sequence.
	 * Any step whose count is reduced to 0 as a result of rewinding is removed entirely from the
	 * sequence. Note that each sleigh step (modification) counts as one step when rewinding.
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
	public Sequence clone() {
		return new Sequence(
			steps.stream().map(Step::clone).collect(Collectors.toList()));
	}

	/**
	 * Obtain a clone of the steps
	 * 
	 * <p>
	 * Modifications to the returned steps have no effect on this sequence.
	 * 
	 * @return the cloned steps
	 */
	public List<Step> getSteps() {
		return steps.stream().map(Step::clone).collect(Collectors.toUnmodifiableList());
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
		if (!(obj instanceof Sequence)) {
			return false;
		}
		Sequence that = (Sequence) obj;
		return Objects.equals(this.steps, that.steps);
	}

	/**
	 * Richly compare to sequences
	 * 
	 * <p>
	 * The result indicates not only which is "less" or "greater" than the other, but also indicates
	 * whether the two are "related." Two sequences are considered related if one is the prefix to
	 * the other. More precisely, they are related if it's possible to transform one into the other
	 * solely by truncation (rewind) or solely by concatenation (advance). When related, the prefix
	 * is considered "less than" the other. Equal sequences are trivially related.
	 * 
	 * <p>
	 * Examples:
	 * <ul>
	 * <li>{@code ""} is related to and less than {@code "10"}</li>
	 * <li>{@code "10"} is related and equal to {@code "10"}</li>
	 * <li>{@code "10"} is related to and less than {@code "11"}</li>
	 * <li>{@code "t1-5"} is related to and less than {@code "t1-5;t2-4"}</li>
	 * <li>{@code "t1-5"} is un-related to and less than {@code "t1-4;t2-4"}</li>
	 * </ul>
	 * 
	 * <p>
	 * The {@link #compareTo(Sequence)} implementation defers to this method. Thus, in a sorted set
	 * of step sequences, the floor of a given sequence is will be the longest prefix in that set to
	 * the given sequence, assuming such a prefix is present.
	 * 
	 * @param that the object of comparison (this being the subject)
	 * @return a result describing the relationship from subject to object
	 */
	public CompareResult compareSeq(Sequence that) {
		int min = Math.min(this.steps.size(), that.steps.size());
		CompareResult result;
		for (int i = 0; i < min; i++) {
			Step s1 = this.steps.get(i);
			Step s2 = that.steps.get(i);
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
	public int compareTo(Sequence that) {
		return compareSeq(that).compareTo;
	}

	/**
	 * Compute the sequence which concatenated to the given prefix would result in this sequence
	 * 
	 * <p>
	 * The returned step sequence should not be manipulated, since it may just be this sequence.
	 * 
	 * @see #compareSeq(Sequence)
	 * @param prefix the prefix
	 * @return the relative sequence from prefix to this
	 * @throws IllegalArgumentException if prefix is not a prefix of this sequence
	 */
	public Sequence relativize(Sequence prefix) {
		if (prefix.isNop()) {
			return this;
		}
		CompareResult comp = compareSeq(prefix);
		Sequence result = new Sequence();
		if (comp == CompareResult.EQUALS) {
			return result;
		}
		if (comp != CompareResult.REL_GT) {
			throw new IllegalArgumentException(String.format(
				"The given prefix (%s) is not actually a prefix of this (%s).", prefix, this));
		}

		int lastStepIndex = prefix.steps.size() - 1;
		Step ancestorLast = prefix.steps.get(lastStepIndex);
		Step continuation = this.steps.get(lastStepIndex);
		result.advance(continuation.subtract(ancestorLast));
		result.steps.addAll(steps.subList(prefix.steps.size(), steps.size()));
		return result;
	}

	/**
	 * Compute to total number of ticks specified
	 * 
	 * @return the total
	 */
	public long totalTickCount() {
		long count = 0;
		for (Step step : steps) {
			count += step.getTickCount();
		}
		return count;
	}

	/**
	 * Compute to total number of patches specified
	 * 
	 * @return the total
	 */
	public long totalPatchCount() {
		long count = 0;
		for (Step step : steps) {
			count += step.getPatchCount();
		}
		return count;
	}

	/**
	 * Execute this sequence upon the given machine
	 * 
	 * <p>
	 * Threads are retrieved from the database by key, then created in the machine (if not already
	 * present) named by {@link TraceThread#getPath()}. The caller should ensure the machine's state
	 * is bound to the given trace.
	 * 
	 * @param trace the trace to which the machine is bound
	 * @param eventThread the thread for the first step, if it applies to the "last thread"
	 * @param machine the machine to step, or null to validate the sequence
	 * @param stepper the actions to step each thread
	 * @param monitor a monitor for cancellation and progress reports
	 * @return the last trace thread stepped during execution
	 * @throws CancelledException if execution is cancelled
	 */
	public <T> TraceThread execute(Trace trace, TraceThread eventThread, PcodeMachine<T> machine,
			Stepper<T> stepper, TaskMonitor monitor) throws CancelledException {
		TraceThreadManager tm = trace.getThreadManager();
		TraceThread thread = eventThread;
		for (Step step : steps) {
			thread = step.execute(tm, thread, machine, stepper, monitor);
		}
		return thread;
	}

	/**
	 * Validate this sequence for the given trace
	 * 
	 * @param trace the trace
	 * @param eventThread the thread for the first step, if it applies to the "last thread"
	 * @return the last trace thread that would be stepped by this sequence
	 */
	public TraceThread validate(Trace trace, TraceThread eventThread) {
		try {
			return execute(trace, eventThread, null, null, null);
		}
		catch (CancelledException e) {
			throw new AssertionError(e);
		}
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
		return steps.get(steps.size() - 1).getThreadKey();
	}
}
