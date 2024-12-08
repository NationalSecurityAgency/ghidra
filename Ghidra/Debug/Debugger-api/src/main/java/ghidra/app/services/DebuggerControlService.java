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
package ghidra.app.services;

import java.util.concurrent.CompletableFuture;

import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.LiveMemoryHandler;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;

@ServiceInfo(
	defaultProviderName = "ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin",
	description = "Centralized service for modifying machine states")
public interface DebuggerControlService {
	interface StateEditor {
		DebuggerControlService getService();

		DebuggerCoordinates getCoordinates();

		boolean isVariableEditable(Address address, int length);

		default boolean isRegisterEditable(Register register) {
			return isVariableEditable(register.getAddress(), register.getNumBytes());
		}

		CompletableFuture<Void> setVariable(Address address, byte[] data);

		default CompletableFuture<Void> setRegister(RegisterValue value) {
			Register register = value.getRegister();
			byte[] bytes = Utils.bigIntegerToBytes(value.getUnsignedValue(), register.getNumBytes(),
				register.isBigEndian());
			return setVariable(register.getAddress(), bytes);
		}
	}

	interface StateEditingMemoryHandler extends StateEditor, LiveMemoryHandler {
	}

	interface ControlModeChangeListener {
		void modeChanged(Trace trace, ControlMode mode);
	}

	ControlMode getCurrentMode(Trace trace);

	void setCurrentMode(Trace trace, ControlMode mode);

	void addModeChangeListener(ControlModeChangeListener listener);

	void removeModeChangeListener(ControlModeChangeListener listener);

	StateEditor createStateEditor(DebuggerCoordinates coordinates);

	/**
	 * Create a state editor whose coordinates follow the trace manager for the given trace
	 * 
	 * @param trace the trace to follow
	 * @return the editor
	 */
	StateEditor createStateEditor(Trace trace);

	StateEditingMemoryHandler createStateEditor(TraceProgramView view);
}
