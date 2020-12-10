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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.impl.dbgeng.client.DebugClientInternal;
import agent.dbgeng.impl.dbgeng.client.DebugClientInternal.DebugClass;
import agent.dbgeng.jna.dbgeng.WinNTExtra.Machine;
import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface2.DbgModelTargetSessionAttributes;
import agent.dbgeng.model.iface2.DbgModelTargetSessionAttributesMachine;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;

public class DbgModelTargetSessionAttributesMachineImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSessionAttributesMachine {

	String ARCH_ATTRIBUTE_NAME = "Arch";
	String DEBUGGER_ATTRIBUTE_NAME = "Debugger";
	String OS_ATTRIBUTE_NAME = "OS";

	public DbgModelTargetSessionAttributesMachineImpl(DbgModelTargetSessionAttributes attributes) {
		super(attributes.getModel(), attributes, "Machine", "SessionMachineAttributes");

		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, "x86_64", //
			DEBUGGER_ATTRIBUTE_NAME, "dbgeng", //
			OS_ATTRIBUTE_NAME, "Windows" //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void sessionAdded(DbgSession session, DbgCause cause) {
		refresh();
	}

	@Override
	public void processAdded(DbgProcess process, DbgCause cause) {
		refresh();
	}

	public void refresh() {
		DebugControl control = getManager().getControl();
		int processorType = control.getActualProcessorType();
		if (processorType < 0) {
			return;
		}
		Machine machine = Machine.getByNumber(processorType);
		int debuggeeType = control.getDebuggeeType();
		DebugClass debugClass = DebugClientInternal.DebugClass.values()[debuggeeType];
		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, machine.description, //
			"Mode", debugClass.toString() //
		), "Refreshed");

		AtomicReference<String> capture = new AtomicReference<>();
		AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getManager().consoleCapture("vertarget").handle(seq::next);
		}, capture).then(seq -> {
			changeAttributes(List.of(), List.of(), Map.of( //
				OS_ATTRIBUTE_NAME, capture.get()), "Refreshed");
		}).finish();
	}

}
