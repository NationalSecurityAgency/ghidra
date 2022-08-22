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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;

/**
 * A p-code machine which sources its state from a trace and can record back into it
 *
 * <p>
 * This is a "mix in" interface. It is part of the SPI, but not the API. That is, emulator
 * developers should use this interface, but emulator clients should not. Clients should use
 * {@link PcodeMachine} instead.
 *
 * @param <T> the type of values manipulated by the machine
 */
public interface TracePcodeMachine<T> extends PcodeMachine<T> {
	/**
	 * Get the trace from which this emulator reads its initial state
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get the snapshot from which this emulator reads its initial state
	 * 
	 * @return the snapshot key
	 */
	long getSnap();

	/**
	 * Get the trace thread corresponding to the given p-code thread
	 * 
	 * @param thread the p-code thread
	 * @return the trace thread
	 */
	default TraceThread getTraceThread(PcodeThread<T> thread) {
		return getTrace().getThreadManager().getLiveThreadByPath(getSnap(), thread.getName());
	}

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
	 * Check if a register has a {@link TraceMemoryState#KNOWN} value for the given thread
	 * 
	 * @param thread the thread
	 * @param register the register
	 * @return true if known
	 */
	default boolean isRegisterKnown(PcodeThread<T> thread, Register register) {
		Trace trace = getTrace();
		long snap = getSnap();
		TraceThread traceThread =
			trace.getThreadManager().getLiveThreadByPath(snap, thread.getName());
		TraceMemoryRegisterSpace space =
			trace.getMemoryManager().getMemoryRegisterSpace(traceThread, false);
		if (space == null) {
			return false;
		}
		return space.getState(snap, register) == TraceMemoryState.KNOWN;
	}

	/**
	 * Initialize the given thread using context from the trace at its program counter
	 * 
	 * @param thread the thread to initialize
	 */
	default void initializeThreadContext(PcodeThread<T> thread) {
		SleighLanguage language = getLanguage();
		Register contextreg = language.getContextBaseRegister();
		if (contextreg != Register.NO_CONTEXT && !isRegisterKnown(thread, contextreg)) {
			RegisterValue context = getTrace().getRegisterContextManager()
					.getValueWithDefault(language, contextreg, getSnap(), thread.getCounter());
			if (context != null) { // TODO: Why does this happen?
				thread.overrideContext(context);
			}
		}
	}

	/**
	 * Write the accumulated emulator state into the given trace at the given snap
	 * 
	 * <p>
	 * <b>NOTE:</b> This method requires a transaction to have already been started on the
	 * destination trace. The destination threads must have equal names/paths at the given
	 * threadsSnap. When using scratch space, threadsSnap should be the source snap. If populating a
	 * new trace, threadsSnap should probably be the destination snap.
	 * 
	 * @param trace the trace to modify
	 * @param destSnap the destination snap within the trace
	 * @param threadsSnap the snap at which to find corresponding threads, usually the same as
	 *            {@link #getSnap()}
	 */
	default void writeDown(Trace trace, long destSnap, long threadsSnap) {
		TracePcodeExecutorState<T> ss = (TracePcodeExecutorState<T>) getSharedState();
		ss.writeDown(trace, destSnap, null, 0);
		TraceThreadManager threadManager = trace.getThreadManager();
		for (PcodeThread<T> emuThread : getAllThreads()) {
			TracePcodeExecutorState<T> ls =
				(TracePcodeExecutorState<T>) emuThread.getState().getLocalState();
			TraceThread traceThread =
				threadManager.getLiveThreadByPath(threadsSnap, emuThread.getName());
			if (traceThread == null) {
				throw new IllegalArgumentException(
					"Given trace does not have thread with name/path '" + emuThread.getName() +
						"' at snap " + destSnap);
			}
			ls.writeDown(trace, destSnap, traceThread, 0);
		}
	}
}
