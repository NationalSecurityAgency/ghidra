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

import ghidra.trace.database.breakpoint.DBTraceBreakpointLocation;
import ghidra.trace.database.breakpoint.DBTraceBreakpointSpec;
import ghidra.trace.database.memory.*;
import ghidra.trace.database.module.DBTraceModule;
import ghidra.trace.database.module.DBTraceSection;
import ghidra.trace.database.stack.DBTraceStack;
import ghidra.trace.database.stack.DBTraceStackFrame;
import ghidra.trace.database.target.iface.*;
import ghidra.trace.database.thread.DBTraceObjectProcess;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.breakpoint.TraceBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointSpec;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.iface.*;
import ghidra.trace.model.thread.TraceProcess;
import ghidra.trace.model.thread.TraceThread;

public class BuiltinTraceObjectInterfaceFactory implements TraceObjectInterfaceFactory {

	private static final List<Constructor<?>> BUILTINS = List.of(
		ctor(TraceActivatable.class, DBTraceObjectActivatable::new),
		ctor(TraceAggregate.class, DBTraceObjectAggregate::new),
		ctor(TraceBreakpointLocation.class, DBTraceBreakpointLocation::new),
		ctor(TraceBreakpointSpec.class, DBTraceBreakpointSpec::new),
		ctor(TraceEnvironment.class, DBTraceObjectEnvironment::new),
		ctor(TraceEventScope.class, DBTraceObjectEventScope::new),
		ctor(TraceExecutionStateful.class, DBTraceObjectExecutionStateful::new),
		ctor(TraceFocusScope.class, DBTraceObjectFocusScope::new),
		ctor(TraceMemory.class, DBTraceObjectMemory::new),
		ctor(TraceMemoryRegion.class, DBTraceMemoryRegion::new),
		ctor(TraceMethod.class, DBTraceObjectMethod::new),
		ctor(TraceModule.class, DBTraceModule::new),
		ctor(TraceProcess.class, DBTraceObjectProcess::new),
		ctor(TraceRegister.class, DBTraceObjectRegister::new),
		ctor(TraceRegisterContainer.class, DBTraceObjectRegisterContainer::new),
		ctor(TraceSection.class, DBTraceSection::new),
		ctor(TraceStack.class, DBTraceStack::new),
		ctor(TraceStackFrame.class, DBTraceStackFrame::new),
		ctor(TraceThread.class, DBTraceThread::new),
		ctor(TraceTogglable.class, DBTraceObjectTogglable::new));

	@Override
	public List<Constructor<?>> getInterfaceConstructors() {
		return BUILTINS;
	}
}
