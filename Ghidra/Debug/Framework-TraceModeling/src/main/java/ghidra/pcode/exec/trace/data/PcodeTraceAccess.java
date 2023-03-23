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
package ghidra.pcode.exec.trace.data;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.trace.TracePcodeMachine;
import ghidra.program.model.lang.Language;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.thread.TraceThread;

/**
 * A trace access shim
 * 
 * <p>
 * This encapsulates the source or destination "coordinates" of a trace to simplify access to that
 * trace by p-code operations. This is also meant to encapsulate certain conventions, e.g., writes
 * are effective from the destination snapshot into the indefinite future, and meant to protect
 * p-code executor/emulator states from future re-factorings of the Trace API.
 * 
 * <p>
 * While, technically anything can be behind the shim, the default implementations are backed by a
 * trace. The shim is associated with a chosen platform and snapshot. All methods are with respect
 * to that platform. In particular the addresses must all be in spaces of the platform's language.
 * Note that the platform may be the trace's host platform.
 * 
 * <p>
 * Typically, each component of an emulator and/or its state will accept a corresponding access
 * shim. Thus, each method in the chain of obtaining the shim is invoked during that piece's
 * construction or invoked and passed into the constructor by a factory method. A complete chain
 * starts with {@link DefaultPcodeTraceAccess}. Each method is listed with notes about where it is
 * typically invoked below:
 * 
 * <ul>
 * <li>Typically invoked by an overloaded constructor, which then passes it to {@code this(...)}.
 * Clients can also construct the shim and pass it to the shim-accepting constructor manually.
 * Similarly, {@link TracePcodeMachine#writeDown(TracePlatform, long, long)} will construct one and
 * pass it to the overloaded method, which can instead be done by the client.
 * 
 * <pre>
 * PcodeTraceAccess access =
 * 	new DefaultPcodeTraceAccess(trace.getPlatformManager().getHostPlatform(), 0, 0);
 * </pre>
 * 
 * <li>Typically invoked by a factory method for an emulator's shared executor state
 * 
 * <pre>
 * PcodeTraceMemoryAccess sharedData = access.getDataForSharedState();
 * </pre>
 * 
 * <li>Typically invoked by a factory method for an emulator thread's local executor state
 * 
 * <pre>
 * PcodeTraceRegisterAccess localData = access.getDataForLocalState(thread, 0);
 * </pre>
 * 
 * <li>Typically invoked by an auxiliary emulator state piece
 * 
 * <pre>
 * PcodeTracePropertyAccess<String> property = data.getPropertyAccess("MyProperty", String.class);
 * </pre>
 * </ul>
 */
public interface PcodeTraceAccess {
	/**
	 * Get the language of the associated platform
	 * 
	 * @return the langauge
	 */
	Language getLanguage();

	/**
	 * Get the data-access shim for use in an emulator's shared state
	 * 
	 * @return the shim
	 */
	PcodeTraceMemoryAccess getDataForSharedState();

	/**
	 * Get the data-access shim for use in an emulator thread's local state
	 * 
	 * @param thread the emulator's thread
	 * @param frame the frame, usually 0
	 * @return the shim
	 */
	PcodeTraceRegistersAccess getDataForLocalState(PcodeThread<?> thread, int frame);

	/**
	 * Get the data-access shim for use in an emulator thread's local state
	 * 
	 * @param thread the trace thread associated with the emulator's thread
	 * @param frame the frame, usually 0
	 * @return the shim
	 */
	PcodeTraceRegistersAccess getDataForLocalState(TraceThread thread, int frame);

	/**
	 * Construct a new trace thread data-access shim
	 * 
	 * @param shared the shared (memory) state
	 * @param local the local (register) state
	 * @return the thread data-access shim
	 */
	default PcodeTraceDataAccess newPcodeTraceThreadAccess(PcodeTraceMemoryAccess shared,
			PcodeTraceRegistersAccess local) {
		return new DefaultPcodeTraceThreadAccess(shared, local);
	}

	/**
	 * Get the data-access shim for use in an executor having thread context
	 * 
	 * <p>
	 * <b>NOTE:</b> Do not use this shim for an emulator thread's local state. Use
	 * {@link #getDataForLocalState(PcodeThread, int)} instead. This shim is meant for use in
	 * stand-alone executors, e.g., for evaluating Sleigh expressions. Most likely, the thread is
	 * the active thread in the UI.
	 * 
	 * @param thread the trace thread for context, if applicable, or null
	 * @param frame the frame
	 * @return the shim
	 */
	default PcodeTraceDataAccess getDataForThreadState(TraceThread thread, int frame) {
		if (thread == null) {
			return getDataForSharedState();
		}
		return newPcodeTraceThreadAccess(getDataForSharedState(),
			getDataForLocalState(thread, frame));
	}
}
