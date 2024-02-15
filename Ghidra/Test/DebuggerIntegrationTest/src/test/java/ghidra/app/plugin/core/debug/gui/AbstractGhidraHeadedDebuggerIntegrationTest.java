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
package ghidra.app.plugin.core.debug.gui;

import java.util.Set;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.debug.api.target.ActionName;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;

public class AbstractGhidraHeadedDebuggerIntegrationTest
		extends AbstractGhidraHeadedDebuggerTest {

	public static final SchemaContext SCHEMA_CTX = xmlSchema("""
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Processes' schema='ProcessContainer' />
			    </schema>
			    <schema name='ProcessContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Process' />
			    </schema>
			    <schema name='Process' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='Aggregate' />
			        <interface name='Process' />
			        <interface name='ExecutionStateful' />
			        <attribute name='Threads' schema='ThreadContainer' />
			        <attribute name='Memory' schema='Memory' />
			        <attribute name='Breakpoints' schema='BreakpointContainer' />
			        <attribute name='State' schema='EXECUTION_STATE' />
			        <attribute-alias from="_state" to="State" />
			    </schema>
			    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='Aggregate' />
			        <interface name='Thread' />
			        <attribute name='Stack' schema='Stack' />
			    </schema>
			    <schema name='Stack' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='Stack' />
			        <element schema='Frame' />
			    </schema>
			    <schema name='Frame' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='Aggregate' />
			        <interface name='StackFrame' />
			        <attribute name='Registers' schema='RegisterContainer' />
			    </schema>
			    <schema name='RegisterContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='RegisterBank' />
			        <interface name='RegisterContainer' />
			        <element schema='Register' />
			    </schema>
			    <schema name='Register' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='Register' />
			    </schema>
			    <schema name='Memory' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='Memory' />
			        <element schema='MemoryRegion' />
			    </schema>
			    <schema name='MemoryRegion' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='MemoryRegion' />
			        <attribute name='Range' schema='RANGE' />
			        <attribute-alias from='_range' to='Range' />
			        <attribute name='R' schema='BOOL' />
			        <attribute-alias from='_readable' to='R' />
			        <attribute name='W' schema='BOOL' />
			        <attribute-alias from='_writable' to='W' />
			        <attribute name='X' schema='BOOL' />
			        <attribute-alias from='_executable' to='X' />
			    </schema>
			    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='BreakpointSpecContainer' />
			        <element schema='BreakpointSpec' />
			    </schema>
			    <schema name='BreakpointSpec' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='BreakpointSpec' />
			        <interface name='BreakpointLocationContainer' />
			        <interface name='Togglable' />
			        <element schema='BreakpointLoc' />
			        <attribute name='Kinds' schema='SET_BREAKPOINT_KIND' />
			        <attribute-alias from='_kinds' to='Kinds' />
			        <attribute name='Expression' schema='STRING' />
			        <attribute-alias from='_expr' to='Expression' />
			        <attribute name='Enabled' schema='BOOL' />
			        <attribute-alias from='_enabled' to='Enabled' />
			    </schema>
			    <schema name='BreakpointLoc' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='BreakpointLocation' />
			        <attribute name='Range' schema='RANGE' />
			        <attribute-alias from='_range' to='Range' />
			    </schema>
			</context>
			""");
	public static final TargetObjectSchema SCHEMA_SESSION =
		SCHEMA_CTX.getSchema(new SchemaName("Session"));

	protected TestTraceRmiConnection rmiCx;

	protected TestRemoteMethod rmiMethodResume;
	protected TestRemoteMethod rmiMethodInterrupt;
	protected TestRemoteMethod rmiMethodKill;
	protected TestRemoteMethod rmiMethodStepInto;
	protected TestRemoteMethod rmiMethodStepOver;
	protected TestRemoteMethod rmiMethodStepOut;

	protected TestRemoteMethod rmiMethodSetHwBreak;
	protected TestRemoteMethod rmiMethodSetSwBreak;
	protected TestRemoteMethod rmiMethodSetReadBreak;
	protected TestRemoteMethod rmiMethodSetWriteBreak;
	protected TestRemoteMethod rmiMethodSetAccessBreak;
	protected TestRemoteMethod rmiMethodToggleBreak;
	protected TestRemoteMethod rmiMethodDeleteBreak;

	protected TestRemoteMethod rmiMethodReadRegs;
	protected TestRemoteMethod rmiMethodWriteReg;

	protected void createRmiConnection() {
		rmiCx = new TestTraceRmiConnection();
	}

	protected void addControlMethods() {
		rmiMethodResume = new TestRemoteMethod("resume", ActionName.RESUME, "Resume",
			"Resume the target", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to resume"));

		rmiMethodInterrupt = new TestRemoteMethod("interrupt", ActionName.INTERRUPT, "Interrupt",
			"Interrupt the target", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to interrupt"));

		rmiMethodKill = new TestRemoteMethod("kill", ActionName.KILL, "Kill",
			"Kill the target", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to kill"));

		rmiMethodStepInto = new TestRemoteMethod("step_into", ActionName.STEP_INTO, "Step Into",
			"Step the thread, descending into subroutines",
			EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));

		rmiMethodStepOver = new TestRemoteMethod("step_over", ActionName.STEP_OVER, "Step Over",
			"Step the thread, without descending into subroutines",
			EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));

		rmiMethodStepOut = new TestRemoteMethod("step_out", ActionName.STEP_OUT, "Step Out",
			"Allow the thread to finish the current subroutine",
			EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));

		TestRemoteMethodRegistry reg = rmiCx.getMethods();
		reg.add(rmiMethodResume);
		reg.add(rmiMethodInterrupt);
		reg.add(rmiMethodKill);
		reg.add(rmiMethodStepInto);
		reg.add(rmiMethodStepOver);
		reg.add(rmiMethodStepOut);
	}

	protected void addBreakpointMethods() {
		rmiMethodSetHwBreak = new TestRemoteMethod("set_hw_break", ActionName.BREAK_HW_EXECUTE,
			"Hardware Breakpoint",
			"Place a hardware execution breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("address", EnumerableTargetObjectSchema.ADDRESS.getName(), true,
				null, "Address", "The desired address"));

		rmiMethodSetSwBreak = new TestRemoteMethod("set_sw_break", ActionName.BREAK_SW_EXECUTE,
			"Software Breakpoint",
			"Place a software execution breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("address", EnumerableTargetObjectSchema.ADDRESS.getName(), true,
				null, "Address", "The desired address"));

		rmiMethodSetReadBreak = new TestRemoteMethod("set_read_break", ActionName.BREAK_READ,
			"Read Breakpoint",
			"Place a read breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", EnumerableTargetObjectSchema.RANGE.getName(), true,
				null, "Range", "The desired address range"));

		rmiMethodSetWriteBreak = new TestRemoteMethod("set_write_break", ActionName.BREAK_WRITE,
			"Write Breakpoint",
			"Place a write breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", EnumerableTargetObjectSchema.RANGE.getName(), true,
				null, "Range", "The desired address range"));

		rmiMethodSetAccessBreak = new TestRemoteMethod("set_acc_break", ActionName.BREAK_ACCESS,
			"Access Breakpoint",
			"Place an access breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", EnumerableTargetObjectSchema.RANGE.getName(), true,
				null, "Range", "The desired address range"));

		rmiMethodToggleBreak = new TestRemoteMethod("toggle_break", ActionName.TOGGLE,
			"Toggle Breakpoint",
			"Toggle a breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("breakpoint", new SchemaName("BreakpointSpec"), true, null,
				"Breakpoint", "The breakpoint to toggle"),
			new TestRemoteParameter("enabled", EnumerableTargetObjectSchema.BOOL.getName(), true,
				null, "Enable", "True to enable. False to disable"));

		rmiMethodDeleteBreak = new TestRemoteMethod("delete_break", ActionName.DELETE,
			"Delete Breakpoint",
			"Delete a breakpoint", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("breakpoint", new SchemaName("BreakpointSpec"), true, null,
				"Breakpoint", "The breakpoint to delete"));

		TestRemoteMethodRegistry reg = rmiCx.getMethods();
		reg.add(rmiMethodSetHwBreak);
		reg.add(rmiMethodSetSwBreak);
		reg.add(rmiMethodSetReadBreak);
		reg.add(rmiMethodSetWriteBreak);
		reg.add(rmiMethodSetAccessBreak);
		reg.add(rmiMethodToggleBreak);
		reg.add(rmiMethodDeleteBreak);
	}

	protected void addRegisterMethods() {
		rmiMethodReadRegs = new TestRemoteMethod("read_regs", ActionName.REFRESH, "Read Registers",
			"Read registers", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("container", new SchemaName("RegisterContainer"), true, null,
				"Registers", "The registers node to read"));

		rmiMethodWriteReg = new TestRemoteMethod("write_reg", ActionName.WRITE_REG,
			"Write Register", "Write a register", EnumerableTargetObjectSchema.VOID.getName(),
			new TestRemoteParameter("frame", new SchemaName("Frame"), false, 0, "Frame",
				"The frame to write to"),
			new TestRemoteParameter("name", EnumerableTargetObjectSchema.STRING.getName(), true,
				null, "Register", "The name of the register to write"),
			new TestRemoteParameter("value", EnumerableTargetObjectSchema.BYTE_ARR.getName(), true,
				null, "Value", "The desired value"));

		TestRemoteMethodRegistry reg = rmiCx.getMethods();
		reg.add(rmiMethodReadRegs);
		reg.add(rmiMethodWriteReg);
	}

	protected TraceObject addMemoryRegion(TraceObjectManager objs, Lifespan lifespan,
			AddressRange range, String name, String flags) {
		String pathStr =
			"Processes[1].Memory[0x%08x:%s]".formatted(range.getMinAddress().getOffset(), name);
		TraceObject regionText = objs.createObject(TraceObjectKeyPath.parse(pathStr));
		regionText.setAttribute(lifespan, "_range", range);
		regionText.setAttribute(lifespan, "_readable", flags.contains("r"));
		regionText.setAttribute(lifespan, "_writable", flags.contains("w"));
		regionText.setAttribute(lifespan, "_executable", flags.contains("x"));
		regionText.insert(lifespan, ConflictResolution.DENY);

		return regionText;
	}

	protected TraceObject ensureBreakpointContainer(TraceObjectManager objs) {
		try (Transaction tx = tb.startTransaction()) {
			return objs.createObject(TraceObjectKeyPath.parse("Processes[1].Breakpoints"));
		}
	}

	protected TraceObject findAndCreateFreeBreakpointSpec(TraceObjectManager objs) {
		TraceObjectKeyPath brkConPath = TraceObjectKeyPath.parse("Processes[1].Breakpoints");
		for (int i = 1; i < 10; i++) {
			TraceObjectKeyPath path = brkConPath.index(i);
			TraceObject exists = objs.getObjectByCanonicalPath(path);
			if (exists == null) {
				return objs.createObject(path);
			}
		}
		throw new AssertionError("More than 10 breakpoints for a test?");
	}

	protected TraceObject addBreakpointAndLoc(TraceObjectManager objs, Lifespan lifespan,
			AddressRange range, Set<TraceBreakpointKind> kinds) {
		try (Transaction tx = objs.getTrace().openTransaction("Add breakpoint")) {
			TraceObject spec = findAndCreateFreeBreakpointSpec(objs);

			spec.setAttribute(lifespan, "_kinds", TraceBreakpointKindSet.encode(kinds));
			spec.setAttribute(lifespan, "_expr", "*0x" + range.getMinAddress());
			spec.setAttribute(lifespan, "_enabled", true);
			spec.insert(lifespan, ConflictResolution.DENY);

			TraceObjectKeyPath specPath = spec.getCanonicalPath();
			TraceObject loc = objs.createObject(specPath.index(0));
			loc.setAttribute(lifespan, "_display", specPath.index());
			loc.setAttribute(lifespan, "_range", range);
			loc.insert(lifespan, ConflictResolution.DENY);
			return spec;
		}
	}
}
