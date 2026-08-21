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
import java.util.List;

import db.Transaction;
import ghidra.app.script.GhidraScript;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.flatapi.FlatDebuggerRmiAPI;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.thread.TraceThread;

public class RefreshRegistersScript extends GhidraScript implements FlatDebuggerRmiAPI {
	public static final List<String> REG_NAMES = List.of("RAX", "RBX");

	@Override
	protected void run() throws Exception {
		DebuggerCoordinates current = getCurrentDebuggerCoordinates();
		if (!current.isAliveAndPresent()) {
			printerr("Target is not alive, or you're looking at the trace history.");
			return;
		}

		try (Transaction tx = current.getTrace().openTransaction("Refresh Registers")) {
		}
	}

	protected void setUnknown(TracePlatform platform, TraceThread thread, int frame, long snap,
			List<Register> regs) {
		TraceMemorySpace regSpace = thread
				.getTrace()
				.getMemoryManager()
				.getMemoryRegisterSpace(thread, frame, false);
		if (regSpace == null) {
			return;
		}
		for (Register reg : regs) {
			regSpace.setState(platform, snap, reg, TraceMemoryState.UNKNOWN);
		}
	}

	protected void readCurrentFrame(DebuggerCoordinates current, boolean forceRefresh) {
		long snap = current.getSnap();
		TracePlatform platform = current.getPlatform();
		List<Register> regs = REG_NAMES.stream().map(platform.getLanguage()::getRegister).toList();
		TraceThread thread = current.getThread();
		int frame = current.getFrame();

		if (forceRefresh) {
			setUnknown(platform, thread, frame, snap, regs);
		}
		readRegisters(platform, thread, frame, snap, regs);
	}

	protected void readAllThreadsTopFrame(DebuggerCoordinates current, boolean forceRefresh) {
		Trace trace = current.getTrace();
		long snap = current.getSnap();
		TracePlatform platform = current.getPlatform();
		List<Register> regs = REG_NAMES.stream().map(platform.getLanguage()::getRegister).toList();

		for (TraceThread thread : trace.getThreadManager().getAllThreads()) {
			if (forceRefresh) {
				setUnknown(platform, thread, 0, snap, regs);
			}
			readRegisters(platform, thread, 0, snap, regs);
		}
	}
}
