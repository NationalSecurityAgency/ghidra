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
package ghidra.dbg.util;

import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Map;

import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibilityListener;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionStateListener;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetInterpreter.TargetInterpreterListener;
import ghidra.dbg.target.TargetMemory.TargetMemoryListener;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.target.TargetRegisterBank.TargetRegisterBankListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public interface AllTargetObjectListenerAdapter
		extends TargetObjectListener, TargetAccessibilityListener,
		TargetExecutionStateListener, TargetFocusScopeListener, TargetInterpreterListener,
		TargetMemoryListener, TargetRegisterBankListener {
	@Override
	default void accessibilityChanged(TargetAccessConditioned object, boolean accessible) {
		//fail();
	}

	@Override
	default void elementsChanged(TargetObject parent, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
		//fail();
	}

	@Override
	default void attributesChanged(TargetObject parent, Collection<String> removed,
			Map<String, ?> added) {
		//fail();
	}

	@Override
	default void consoleOutput(TargetObject console, Channel channel, byte[] out) {
		//fail();
	}

	@Override
	default void displayChanged(TargetObject object, String display) {
		//fail();
	}

	@Override
	default void executionStateChanged(TargetExecutionStateful object,
			TargetExecutionState state) {
		//fail();
	}

	@Override
	default void focusChanged(TargetFocusScope object, TargetObject focused) {
		//fail();
	}

	@Override
	default void memoryUpdated(TargetMemory memory, Address address, byte[] data) {
		//fail();
	}

	@Override
	default void memoryReadError(TargetMemory memory, AddressRange range,
			DebuggerMemoryAccessException e) {
		fail();
	}

	@Override
	default void promptChanged(TargetInterpreter interpreter, String prompt) {
		//fail();
	}

	@Override
	default void registersUpdated(TargetRegisterBank bank, Map<String, byte[]> updates) {
		//fail();
	}
}
