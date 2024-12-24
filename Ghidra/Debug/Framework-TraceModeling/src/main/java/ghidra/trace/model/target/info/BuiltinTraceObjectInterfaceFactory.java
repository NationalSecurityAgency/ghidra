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
package ghidra.trace.model.target.info;

import static ghidra.trace.model.target.info.TraceObjectInterfaceFactory.ctor;

import java.util.List;

import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointLocation;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointSpec;
import ghidra.trace.database.memory.*;
import ghidra.trace.database.module.*;
import ghidra.trace.database.stack.DBTraceObjectStack;
import ghidra.trace.database.stack.DBTraceObjectStackFrame;
import ghidra.trace.database.target.iface.*;
import ghidra.trace.database.thread.DBTraceObjectProcess;
import ghidra.trace.database.thread.DBTraceObjectThread;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointSpec;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceObjectModule;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.iface.*;
import ghidra.trace.model.thread.TraceObjectProcess;
import ghidra.trace.model.thread.TraceObjectThread;

public class BuiltinTraceObjectInterfaceFactory implements TraceObjectInterfaceFactory {

	private static final List<Constructor<?>> BUILTINS = List.of(
		ctor(TraceObjectActivatable.class, DBTraceObjectActivatable::new),
		ctor(TraceObjectAggregate.class, DBTraceObjectAggregate::new),
		ctor(TraceObjectBreakpointLocation.class, DBTraceObjectBreakpointLocation::new),
		ctor(TraceObjectBreakpointSpec.class, DBTraceObjectBreakpointSpec::new),
		ctor(TraceObjectEnvironment.class, DBTraceObjectEnvironment::new),
		ctor(TraceObjectEventScope.class, DBTraceObjectEventScope::new),
		ctor(TraceObjectExecutionStateful.class, DBTraceObjectExecutionStateful::new),
		ctor(TraceObjectFocusScope.class, DBTraceObjectFocusScope::new),
		ctor(TraceObjectMemory.class, DBTraceObjectMemory::new),
		ctor(TraceObjectMemoryRegion.class, DBTraceObjectMemoryRegion::new),
		ctor(TraceObjectMethod.class, DBTraceObjectMethod::new),
		ctor(TraceObjectModule.class, DBTraceObjectModule::new),
		ctor(TraceObjectProcess.class, DBTraceObjectProcess::new),
		ctor(TraceObjectRegister.class, DBTraceObjectRegister::new),
		ctor(TraceObjectRegisterContainer.class, DBTraceObjectRegisterContainer::new),
		ctor(TraceObjectSection.class, DBTraceObjectSection::new),
		ctor(TraceObjectStack.class, DBTraceObjectStack::new),
		ctor(TraceObjectStackFrame.class, DBTraceObjectStackFrame::new),
		ctor(TraceObjectThread.class, DBTraceObjectThread::new),
		ctor(TraceObjectTogglable.class, DBTraceObjectTogglable::new));

	@Override
	public List<Constructor<?>> getInterfaceConstructors() {
		return BUILTINS;
	}
}
