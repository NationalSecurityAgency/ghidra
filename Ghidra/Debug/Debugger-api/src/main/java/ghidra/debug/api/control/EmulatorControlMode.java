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
package ghidra.debug.api.control;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import generic.theme.GIcon;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.program.TraceVariableSnapProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.PatchStep;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.trace.util.TraceRegisterUtils;

public class EmulatorControlMode extends ControlMode {

	public EmulatorControlMode() {
		super("Default Concrete P-code Emulator",
			new GIcon("icon.debugger.control.mode.rw.emulator"),
			new GIcon("icon.debugger.emulate"));
		isEditEnabled = true;
	}

	public EmulatorControlMode(EmulatorFactory factory) {
		super(factory.getTitle(), new GIcon("icon.debugger.control.mode.rw.emulator"),
			new GIcon("icon.debugger.emulate"));
		isEditEnabled = true;
	}

	@Override
	public boolean isTarget() {
		return false;
	}

	@Override
	public boolean followsPresent() {
		return false;
	}

	@Override
	public boolean canEdit(DebuggerCoordinates coordinates) {
		return isEditEnabled && coordinates.getTrace() != null;
	}

	@Override
	public boolean isVariableEditable(DebuggerCoordinates coordinates, Address address,
			int length) {
		if (coordinates.getThread() == null) {
			// A limitation in TraceSchedule, which is used to manifest patches
			return false;
		}
		if (!address.isMemoryAddress() && coordinates.getThread() == null) {
			return false;
		}
		// LATER: Limitation from using Sleigh for patching
		Register ctxReg = coordinates.getTrace().getBaseLanguage().getContextBaseRegister();
		if (ctxReg == Register.NO_CONTEXT) {
			return true;
		}
		AddressRange ctxRange = TraceRegisterUtils.rangeForRegister(ctxReg);
		if (ctxRange.contains(address)) {
			return false;
		}
		return true;
	}

	@Override
	public CompletableFuture<Void> setVariable(PluginTool tool,
			DebuggerCoordinates coordinates, Address address, byte[] data) {
		if (!(coordinates.getView() instanceof TraceVariableSnapProgramView)) {
			throw new IllegalArgumentException("Cannot emulate using a Fixed Program View");
		}
		TraceThread thread = coordinates.getThread();
		if (thread == null) {
			// TODO: Well, technically, only for register edits
			// It's a limitation in TraceSchedule. Every step requires a thread
			throw new IllegalArgumentException("Emulator edits require a thread.");
		}
		Language language = coordinates.getPlatform().getLanguage();
		TraceSchedule time = coordinates.getTime()
				.patched(thread, language, PatchStep.generateSleigh(language, address, data));

		DebuggerCoordinates withTime = coordinates.time(time);
		DebuggerTraceManagerService traceManager =
			Objects.requireNonNull(tool.getService(DebuggerTraceManagerService.class),
				"No trace manager service");

		return traceManager.activateAndNotify(withTime, ActivationCause.EMU_STATE_EDIT);
	}

	@Override
	public boolean useEmulatedBreakpoints() {
		return true;
	}

}
