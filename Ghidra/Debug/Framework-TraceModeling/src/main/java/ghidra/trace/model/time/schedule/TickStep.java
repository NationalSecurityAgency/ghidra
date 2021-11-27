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

import java.util.function.Consumer;

import ghidra.pcode.emu.PcodeThread;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A step of a given thread in a schedule: repeating some number of ticks
 */
public class TickStep implements Step {

	public static TickStep parse(long threadKey, String stepSpec) {
		try {
			return new TickStep(threadKey, Long.parseLong(stepSpec));
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Cannot parse step: '" + stepSpec + "'");
		}
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
	public int getTypeOrder() {
		return 0;
	}

	@Override
	public String toString() {
		if (threadKey == -1) {
			return Long.toString(tickCount);
		}
		return String.format("t%d-%d", threadKey, tickCount);
	}

	@Override
	public boolean isNop() {
		return tickCount == 0;
	}

	@Override
	public long getThreadKey() {
		return threadKey;
	}

	@Override
	public long getTickCount() {
		return tickCount;
	}

	@Override
	public long getPatchCount() {
		return 0;
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

	@Override
	public long rewind(long steps) {
		if (steps < 0) {
			throw new IllegalArgumentException("Cannot rewind a negative number");
		}
		long diff = this.tickCount - steps;
		this.tickCount = Long.max(0, diff);
		return -diff;
	}

	@Override
	public boolean isCompatible(Step step) {
		if (!(step instanceof TickStep)) {
			return false;
		}
		TickStep ts = (TickStep) step;
		return this.threadKey == ts.threadKey || ts.threadKey == -1;
	}

	@Override
	public void addTo(Step step) {
		assert isCompatible(step);
		TickStep ts = (TickStep) step;
		advance(ts.tickCount);
	}

	@Override
	public Step subtract(Step step) {
		assert isCompatible(step);
		TickStep that = (TickStep) step;
		return new TickStep(this.threadKey, this.tickCount - that.tickCount);
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
	public CompareResult compareStep(Step step) {
		CompareResult result;

		result = compareStepType(step);
		if (result != CompareResult.EQUALS) {
			return result;
		}

		TickStep that = (TickStep) step;
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

	@Override
	public <T> void execute(PcodeThread<T> emuThread, Consumer<PcodeThread<T>> stepAction,
			TaskMonitor monitor) throws CancelledException {
		for (int i = 0; i < tickCount; i++) {
			monitor.incrementProgress(1);
			monitor.checkCanceled();
			stepAction.accept(emuThread);
		}
	}
}
