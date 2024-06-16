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

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A generator of an emulator's thread schedule
 */
public interface Scheduler {

	/**
	 * Create a scheduler that allocates all slices to a single thread
	 * 
	 * @param thread the thread to schedule
	 * @return the scheduler
	 */
	static Scheduler oneThread(TraceThread thread) {
		long key = thread == null ? -1 : thread.getKey();
		return new Scheduler() {
			@Override
			public TickStep nextSlice(Trace trace) {
				return new TickStep(key, 1000);
			}
		};
	}

	interface RunResult {
		/**
		 * Get the actual schedule executed
		 * 
		 * <p>
		 * It is possible for the machine to be interrupted mid-instruction. If this is the case,
		 * the trace schedule will indicate the p-code steps taken.
		 * 
		 * @return the schedule
		 */
		public TraceSchedule schedule();

		/**
		 * Get the error that interrupted execution
		 * 
		 * <p>
		 * Ideally, this is a {@link InterruptPcodeExecutionException}, indicating a breakpoint
		 * trapped the emulator, but it could be a number of things:
		 * 
		 * <ul>
		 * <li>An instruction decode error</li>
		 * <li>An unimplemented instruction</li>
		 * <li>An unimplemented p-code userop</li>
		 * <li>An error accessing the machine state</li>
		 * <li>A runtime error in the implementation of a p-code userop</li>
		 * <li>A runtime error in the implementation of the emulator, in which case, a bug should be
		 * filed</li>
		 * </ul>
		 * 
		 * @return the error
		 */
		public Throwable error();
	}

	/**
	 * The result of running a machine
	 */
	record RecordRunResult(TraceSchedule schedule, Throwable error) implements RunResult {
	}

	/**
	 * Get the next step to schedule
	 * 
	 * @return the (instruction-level) thread and tick count
	 */
	TickStep nextSlice(Trace trace);

	/**
	 * Run a machine according to the given schedule until it is interrupted
	 * 
	 * <p>
	 * This method will drop p-code steps from injections, including those from execution
	 * breakpoints. The goal is to ensure that the returned schedule can be used to recover the same
	 * state on a machine without injections. Unfortunately, injections which modify the machine
	 * state, other than unique variables, will defeat that goal.
	 * 
	 * @param trace the trace whose threads to schedule
	 * @param eventThread the first thread to schedule if the scheduler doesn't specify
	 * @param machine the machine to run
	 * @param monitor a monitor for cancellation
	 * @return the result of execution
	 */
	default RunResult run(Trace trace, TraceThread eventThread, PcodeMachine<?> machine,
			TaskMonitor monitor) {
		TraceThreadManager tm = trace.getThreadManager();
		TraceSchedule completedSteps = TraceSchedule.snap(0);
		PcodeThread<?> emuThread = null;
		int completedTicks = 0;
		try {
			while (true) {
				TickStep slice = nextSlice(trace);
				eventThread = slice.getThread(tm, eventThread);
				emuThread = machine.getThread(eventThread.getPath(), true);
				if (emuThread.getFrame() != null) {
					emuThread.finishInstruction();
				}
				for (int i = 0; i < slice.tickCount; i++) {
					monitor.checkCancelled();
					emuThread.stepInstruction();
					completedTicks++;
				}
				completedSteps = completedSteps.steppedForward(eventThread, completedTicks);
				completedTicks = 0;
			}
		}
		catch (PcodeExecutionException e) {
			completedSteps = completedSteps.steppedForward(eventThread, completedTicks);
			PcodeFrame frame = emuThread.getFrame();
			if (frame == null) {
				return new RecordRunResult(completedSteps, e);
			}
			// Rewind one so stepping retries the op causing the error
			frame.stepBack();
			int count = frame.count();
			if (count == 0) {
				// If we've decoded, but could not execute the first op, just drop the p-code steps
				emuThread.dropInstruction();
				return new RecordRunResult(completedSteps, e);
			}
			// The +1 accounts for the decode step
			return new RecordRunResult(
				completedSteps.steppedPcodeForward(eventThread, count + 1), e);
		}
		catch (CancelledException e) {
			return new RecordRunResult(
				completedSteps.steppedForward(eventThread, completedTicks), e);
		}
	}
}
