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
package ghidra.pcode.exec.trace;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.trace.data.*;
import ghidra.trace.model.guest.TracePlatform;

/**
 * A p-code machine which sources its state from a trace and can record back into it
 *
 * @param <T> the type of values manipulated by the machine
 */
public interface TracePcodeMachine<T> extends PcodeMachine<T> {

	/**
	 * Create a shared state
	 * 
	 * @return the shared state
	 */
	TracePcodeExecutorState<T> createSharedState();

	/**
	 * Create a local state
	 * 
	 * @param thread the thread whose state is being created
	 * @return the local state
	 */
	TracePcodeExecutorState<T> createLocalState(PcodeThread<T> thread);

	/**
	 * Write the accumulated emulator state via the given trace access shim
	 * 
	 * <p>
	 * <b>NOTE:</b> This method requires a transaction to have already been started on the
	 * destination trace. The destination threads must have equal names/paths at the given
	 * threadsSnap. When using scratch space, threadsSnap should be the source snap. If populating a
	 * new trace, threadsSnap should probably be the destination snap.
	 * 
	 * @param into the destination trace-data access shim
	 */
	default void writeDown(PcodeTraceAccess into) {
		TracePcodeExecutorState<T> sharedState = (TracePcodeExecutorState<T>) getSharedState();
		sharedState.writeDown(into.getDataForSharedState());
		for (PcodeThread<T> emuThread : getAllThreads()) {
			PcodeTraceDataAccess localInto = into.getDataForLocalState(emuThread, 0);
			if (localInto == null) {
				throw new IllegalArgumentException(
					"Given trace does not have thread with name/path '" + emuThread.getName() +
						"' at source snap");
			}
			TracePcodeExecutorState<T> localState =
				(TracePcodeExecutorState<T>) emuThread.getState().getLocalState();
			localState.writeDown(localInto);
		}
	}

	/**
	 * @see #writeDown(PcodeTraceAccess)
	 * @param platform the platform whose trace to modify
	 * @param destSnap the destination snap within the trace
	 * @param threadsSnap the snap at which to find corresponding threads, usually the same as
	 *            {@link #getSnap()}
	 */
	default void writeDown(TracePlatform platform, long destSnap, long threadsSnap) {
		writeDown(new DefaultPcodeTraceAccess(platform, destSnap, threadsSnap));
	}
}
