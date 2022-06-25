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

import javax.swing.Icon;

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.service.editing.DebuggerStateEditingServicePlugin;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.LiveMemoryHandler;
import ghidra.trace.model.Trace;
import ghidra.trace.model.program.TraceProgramView;

@ServiceInfo(
	defaultProvider = DebuggerStateEditingServicePlugin.class,
	description = "Centralized service for modifying machine states")
public interface DebuggerStateEditingService {
	enum StateEditingMode {
		READ_ONLY(DebuggerResources.NAME_EDIT_MODE_READ_ONLY, //
				DebuggerResources.ICON_EDIT_MODE_READ_ONLY) {
			@Override
			public boolean canEdit(DebuggerCoordinates coordinates) {
				return false;
			}
		},
		WRITE_TARGET(DebuggerResources.NAME_EDIT_MODE_WRITE_TARGET, //
				DebuggerResources.ICON_EDIT_MODE_WRITE_TARGET) {
			@Override
			public boolean canEdit(DebuggerCoordinates coordinates) {
				return coordinates.isAliveAndPresent();
			}
		},
		WRITE_TRACE(DebuggerResources.NAME_EDIT_MODE_WRITE_TRACE, //
				DebuggerResources.ICON_EDIT_MODE_WRITE_TRACE) {
			@Override
			public boolean canEdit(DebuggerCoordinates coordinates) {
				return coordinates.getTrace() != null;
			}
		},
		WRITE_EMULATOR(DebuggerResources.NAME_EDIT_MODE_WRITE_EMULATOR, //
				DebuggerResources.ICON_EDIT_MODE_WRITE_EMULATOR) {
			@Override
			public boolean canEdit(DebuggerCoordinates coordinates) {
				return coordinates.getTrace() != null;
			}
		};

		public final String name;
		public final Icon icon;

		private StateEditingMode(String name, Icon icon) {
			this.name = name;
			this.icon = icon;
		}

		public abstract boolean canEdit(DebuggerCoordinates coordinates);
	}

	interface StateEditor {
		DebuggerStateEditingService getService();

		DebuggerCoordinates getCoordinates();

		boolean isVariableEditable(Address address, int length);

		default boolean isRegisterEditable(Register register) {
			return isVariableEditable(register.getAddress(), register.getNumBytes());
		}

		CompletableFuture<Void> setVariable(Address address, byte[] data);

		default CompletableFuture<Void> setRegister(RegisterValue value) {
			Register register = value.getRegister();
			boolean isBigEndian = getCoordinates().getTrace().getBaseLanguage().isBigEndian();
			byte[] bytes = Utils.bigIntegerToBytes(value.getUnsignedValue(), register.getNumBytes(),
				isBigEndian);
			return setVariable(register.getAddress(), bytes);
		}
	}

	interface StateEditingMemoryHandler extends StateEditor, LiveMemoryHandler {
	}

	interface StateEditingModeChangeListener {
		void modeChanged(Trace trace, StateEditingMode mode);
	}

	StateEditingMode getCurrentMode(Trace trace);

	void setCurrentMode(Trace trace, StateEditingMode mode);

	void addModeChangeListener(StateEditingModeChangeListener listener);

	void removeModeChangeListener(StateEditingModeChangeListener listener);

	StateEditor createStateEditor(DebuggerCoordinates coordinates);

	StateEditor createStateEditor(Trace trace);

	StateEditingMemoryHandler createStateEditor(TraceProgramView view);
}
