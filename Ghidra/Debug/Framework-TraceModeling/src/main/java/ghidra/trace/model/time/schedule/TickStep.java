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

/**
 * A step of a given thread in a schedule: repeating some number of ticks
 */
public class TickStep extends AbstractStep {

	public static TickStep parse(long threadKey, String stepSpec) {
		try {
			return new TickStep(threadKey, Long.parseLong(stepSpec));
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException("Cannot parse tick step: '" + stepSpec + "'");
		}
	}

	/**
	 * Construct a tick step for the given thread with the given tick count
	 * 
	 * @param threadKey the key of the thread in the trace, -1 for the "last thread"
	 * @param tickCount the number of ticks to step on the thread
	 */
	public TickStep(long threadKey, long tickCount) {
		super(threadKey, tickCount);
	}

	@Override
	public StepType getType() {
		return StepType.TICK;
	}

	@Override
	protected String toStringStepPart() {
		return Long.toString(tickCount);
	}

	@Override
	public TickStep clone() {
		return new TickStep(threadKey, tickCount);
	}

	@Override
	public Step subtract(Step step) {
		assert isCompatible(step);
		TickStep that = (TickStep) step;
		return new TickStep(this.threadKey, this.tickCount - that.tickCount);
	}

	@Override
	public <T> void execute(PcodeThread<T> emuThread, Stepper stepper, TaskMonitor monitor)
			throws CancelledException {
		for (int i = 0; i < tickCount; i++) {
			monitor.incrementProgress(1);
			monitor.checkCancelled();
			stepper.tick(emuThread);
		}
	}
}
