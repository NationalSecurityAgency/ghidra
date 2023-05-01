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

import ghidra.pcode.emu.PcodeThread;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SkipStep extends AbstractStep {

	public static SkipStep parse(long threadKey, String stepSpec) {
		if (!stepSpec.startsWith("s")) {
			throw new IllegalArgumentException("Cannot parse skip step: '" + stepSpec + "'");
		}
		try {
			return new SkipStep(threadKey, Long.parseLong(stepSpec.substring(1)));
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Cannot parse skip step: '" + stepSpec + "'");
		}
	}

	/**
	 * Construct a skip step for the given thread with the given tick count
	 * 
	 * @param threadKey the key of the thread in the trace, -1 for the "last thread"
	 * @param tickCount the number of ticks to skip on the thread
	 */
	public SkipStep(long threadKey, long tickCount) {
		super(threadKey, tickCount);
	}

	@Override
	public StepType getType() {
		return StepType.SKIP;
	}

	@Override
	protected String toStringStepPart() {
		return String.format("s%d", tickCount);
	}

	@Override
	public AbstractStep clone() {
		return new SkipStep(threadKey, tickCount);
	}

	@Override
	public Step subtract(Step step) {
		assert isCompatible(step);
		SkipStep that = (SkipStep) step;
		return new SkipStep(this.threadKey, this.tickCount - that.tickCount);
	}

	@Override
	public <T> void execute(PcodeThread<T> emuThread, Stepper stepper, TaskMonitor monitor)
			throws CancelledException {
		for (int i = 0; i < tickCount; i++) {
			monitor.incrementProgress(1);
			monitor.checkCancelled();
			stepper.skip(emuThread);
		}
	}
}
