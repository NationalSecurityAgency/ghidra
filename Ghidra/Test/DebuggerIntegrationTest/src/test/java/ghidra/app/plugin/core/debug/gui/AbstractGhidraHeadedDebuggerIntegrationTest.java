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

import static org.junit.Assert.assertEquals;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.commons.lang3.ArrayUtils;

import db.Transaction;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.*;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.target.ActionName;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceBreakpointKind.TraceBreakpointKindSet;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectManager;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.util.NumericUtilities;

public class AbstractGhidraHeadedDebuggerIntegrationTest
		extends AbstractGhidraHeadedDebuggerTest {

	public static final SchemaContext SCHEMA_CTX = xmlSchema("""
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <interface name='EventScope' />
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
			        <element schema='BreakpointSpec' />
			    </schema>
			    <schema name='BreakpointSpec' canonical='yes' elementResync='NEVER'
			            attributeResync='ONCE'>
			        <interface name='BreakpointSpec' />
			        <interface name='Togglable' />
			        <element schema='BreakpointLoc' />
			        <attribute name='Kinds' schema='STRING' />
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
	public static final TraceObjectSchema SCHEMA_SESSION =
		SCHEMA_CTX.getSchema(new SchemaName("Session"));

	protected TestTraceRmiConnection rmiCx;

	protected TestRemoteMethod rmiMethodExecute;

	protected TestRemoteMethod rmiMethodActivateProcess;
	protected TestRemoteMethod rmiMethodActivateThread;
	protected TestRemoteMethod rmiMethodActivateFrame;

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

	protected TestRemoteMethod rmiMethodReadMem;
	protected TestRemoteMethod rmiMethodWriteMem;

	protected void createRmiConnection() {
		rmiCx = new TestTraceRmiConnection() {
			@Override
			protected DebuggerTraceManagerService getTraceManager() {
				return traceManager;
			}

			@Override
			protected DebuggerControlService getControlService() {
				return tool.getService(DebuggerControlService.class);
			}
		};
	}

	protected void addExecuteMethod() {
		rmiMethodExecute = new TestRemoteMethod("execute", ActionName.EXECUTE, "Execute",
			"Execut a CLI command", PrimitiveTraceObjectSchema.STRING,
			new TestRemoteParameter("cmd", PrimitiveTraceObjectSchema.STRING, true, null,
				"Command", "The command to execute"),
			new TestRemoteParameter("to_string", PrimitiveTraceObjectSchema.BOOL, true, false,
				"To String", "Capture output to string"));

		rmiCx.getMethods().add(rmiMethodExecute);
	}

	protected void addActivateMethods() {
		rmiMethodActivateProcess =
			new TestRemoteMethod("activate_process", ActionName.ACTIVATE, "Activate Process",
				"Activate a process", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
					"The process to activate"));

		rmiMethodActivateThread =
			new TestRemoteMethod("activate_thread", ActionName.ACTIVATE, "Activate Thread",
				"Activate a thread", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
					"The thread to activate"));

		rmiMethodActivateFrame =
			new TestRemoteMethod("activate_frame", ActionName.ACTIVATE, "Activate Frame",
				"Activate a frame", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("frame", new SchemaName("Frame"), true, null, "Frame",
					"The frame to activate"));

		rmiCx.getMethods().add(rmiMethodActivateProcess);
		rmiCx.getMethods().add(rmiMethodActivateThread);
		rmiCx.getMethods().add(rmiMethodActivateFrame);
	}

	protected void addActivateWithSnapMethods() {
		rmiMethodActivateProcess =
			new TestRemoteMethod("activate_process", ActionName.ACTIVATE, "Activate Process",
				"Activate a process", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
					"The process to activate"),
				new TestRemoteParameter("snap", PrimitiveTraceObjectSchema.LONG, false, null,
					"Time", "The snapshot to activate"));

		rmiMethodActivateThread =
			new TestRemoteMethod("activate_thread", ActionName.ACTIVATE, "Activate Thread",
				"Activate a thread", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
					"The thread to activate"),
				new TestRemoteParameter("snap", PrimitiveTraceObjectSchema.LONG, false, null,
					"Time", "The snapshot to activate"));

		rmiMethodActivateFrame =
			new TestRemoteMethod("activate_frame", ActionName.ACTIVATE, "Activate Frame",
				"Activate a frame", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("frame", new SchemaName("Frame"), true, null, "Frame",
					"The frame to activate"),
				new TestRemoteParameter("snap", PrimitiveTraceObjectSchema.LONG, false, null,
					"Time", "The snapshot to activate"));

		rmiCx.getMethods().add(rmiMethodActivateProcess);
		rmiCx.getMethods().add(rmiMethodActivateThread);
		rmiCx.getMethods().add(rmiMethodActivateFrame);
	}

	protected void addActivateWithTimeMethods() {
		rmiMethodActivateProcess =
			new TestRemoteMethod("activate_process", ActionName.ACTIVATE, "Activate Process",
				"Activate a process", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
					"The process to activate"),
				new TestRemoteParameter("time", PrimitiveTraceObjectSchema.STRING, false, null,
					"Time", "The schedule to activate"));

		rmiMethodActivateThread =
			new TestRemoteMethod("activate_thread", ActionName.ACTIVATE, "Activate Thread",
				"Activate a thread", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
					"The thread to activate"),
				new TestRemoteParameter("time", PrimitiveTraceObjectSchema.STRING, false, null,
					"Time", "The schedule to activate"));

		rmiMethodActivateFrame =
			new TestRemoteMethod("activate_frame", ActionName.ACTIVATE, "Activate Frame",
				"Activate a frame", PrimitiveTraceObjectSchema.VOID,
				new TestRemoteParameter("frame", new SchemaName("Frame"), true, null, "Frame",
					"The frame to activate"),
				new TestRemoteParameter("time", PrimitiveTraceObjectSchema.STRING, false, null,
					"Time", "The schedule to activate"));

		rmiCx.getMethods().add(rmiMethodActivateProcess);
		rmiCx.getMethods().add(rmiMethodActivateThread);
		rmiCx.getMethods().add(rmiMethodActivateFrame);
	}

	protected boolean activationMethodsQueuesEmpty() {
		return rmiMethodActivateProcess.argQueue().isEmpty() &&
			rmiMethodActivateThread.argQueue().isEmpty() &&
			rmiMethodActivateFrame.argQueue().isEmpty();
	}

	protected void addControlMethods() {
		rmiMethodResume = new TestRemoteMethod("resume", ActionName.RESUME, "Resume",
			"Resume the target", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to resume"));

		rmiMethodInterrupt = new TestRemoteMethod("interrupt", ActionName.INTERRUPT, "Interrupt",
			"Interrupt the target", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to interrupt"));

		rmiMethodKill = new TestRemoteMethod("kill", ActionName.KILL, "Kill",
			"Kill the target", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process to kill"));

		rmiMethodStepInto = new TestRemoteMethod("step_into", ActionName.STEP_INTO, "Step Into",
			"Step the thread, descending into subroutines", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));

		rmiMethodStepOver = new TestRemoteMethod("step_over", ActionName.STEP_OVER, "Step Over",
			"Step the thread, without descending into subroutines",
			PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));

		rmiMethodStepOut = new TestRemoteMethod("step_out", ActionName.STEP_OUT, "Step Out",
			"Allow the thread to finish the current subroutine", PrimitiveTraceObjectSchema.VOID,
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
			"Hardware Breakpoint", "Place a hardware execution breakpoint",
			PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("address", PrimitiveTraceObjectSchema.ADDRESS, true,
				null, "Address", "The desired address"));

		rmiMethodSetSwBreak = new TestRemoteMethod("set_sw_break", ActionName.BREAK_SW_EXECUTE,
			"Software Breakpoint", "Place a software execution breakpoint",
			PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("address", PrimitiveTraceObjectSchema.ADDRESS, true,
				null, "Address", "The desired address"));

		rmiMethodSetReadBreak = new TestRemoteMethod("set_read_break", ActionName.BREAK_READ,
			"Read Breakpoint", "Place a read breakpoint", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", PrimitiveTraceObjectSchema.RANGE, true,
				null, "Range", "The desired address range"));

		rmiMethodSetWriteBreak = new TestRemoteMethod("set_write_break", ActionName.BREAK_WRITE,
			"Write Breakpoint", "Place a write breakpoint", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", PrimitiveTraceObjectSchema.RANGE, true,
				null, "Range", "The desired address range"));

		rmiMethodSetAccessBreak = new TestRemoteMethod("set_acc_break", ActionName.BREAK_ACCESS,
			"Access Breakpoint", "Place an access breakpoint", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null, "Process",
				"The process in which to place the breakpoint"),
			new TestRemoteParameter("range", PrimitiveTraceObjectSchema.RANGE, true,
				null, "Range", "The desired address range"));

		rmiMethodToggleBreak = new TestRemoteMethod("toggle_break", ActionName.TOGGLE,
			"Toggle Breakpoint", "Toggle a breakpoint", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("breakpoint", new SchemaName("BreakpointSpec"), true, null,
				"Breakpoint", "The breakpoint to toggle"),
			new TestRemoteParameter("enabled", PrimitiveTraceObjectSchema.BOOL, true,
				null, "Enable", "True to enable. False to disable"));

		rmiMethodDeleteBreak = new TestRemoteMethod("delete_break", ActionName.DELETE,
			"Delete Breakpoint", "Delete a breakpoint", PrimitiveTraceObjectSchema.VOID,
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
			"Read registers", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("container", new SchemaName("RegisterContainer"), true, null,
				"Registers", "The registers node to read"));

		rmiMethodWriteReg = new TestRemoteMethod("write_reg", ActionName.WRITE_REG,
			"Write Register", "Write a register", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("frame", new SchemaName("Frame"), false, 0, "Frame",
				"The frame to write to"),
			new TestRemoteParameter("name", PrimitiveTraceObjectSchema.STRING, true,
				null, "Register", "The name of the register to write"),
			new TestRemoteParameter("value", PrimitiveTraceObjectSchema.BYTE_ARR, true,
				null, "Value", "The desired value"));

		TestRemoteMethodRegistry reg = rmiCx.getMethods();
		reg.add(rmiMethodReadRegs);
		reg.add(rmiMethodWriteReg);
	}

	protected void handleReadRegsInvocation(TraceObject container, Callable<Object> action)
			throws Throwable {
		Map<String, Object> args = rmiMethodReadRegs.expect();
		rmiMethodReadRegs.result(action.call());
		assertEquals(Map.ofEntries(
			Map.entry("container", container)),
			args);
	}

	protected void handleWriteRegInvocation(TraceStackFrame frame, String name, long value)
			throws Throwable {
		Map<String, Object> args = rmiMethodWriteReg.expect();
		rmiMethodWriteReg.result(null);
		assertEquals(Set.of("frame", "name", "value"), args.keySet());
		assertEquals(frame.getObject(), args.get("frame"));
		assertEquals(name, args.get("name"));
		byte[] bytes = (byte[]) args.get("value");
		assertEquals(value, Utils.bytesToLong(bytes, bytes.length, true));
	}

	protected void addMemoryMethods() {
		rmiMethodReadMem = new TestRemoteMethod("read_mem", ActionName.READ_MEM, "Read Memory",
			"Read memory", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null,
				"Process", "The process whose memory to read"),
			new TestRemoteParameter("range", PrimitiveTraceObjectSchema.RANGE, true, null,
				"Range", "The address range to read"));

		rmiMethodWriteMem = new TestRemoteMethod("write_mem", ActionName.WRITE_MEM, "Write Memory",
			"Write memory", PrimitiveTraceObjectSchema.VOID,
			new TestRemoteParameter("process", new SchemaName("Process"), true, null,
				"Process", "The process whose memory to read"),
			new TestRemoteParameter("start", PrimitiveTraceObjectSchema.ADDRESS, true, null,
				"Start", "The address to start writing"),
			new TestRemoteParameter("data", PrimitiveTraceObjectSchema.BYTE_ARR, true, null,
				"Data", "The data to write"));

		TestRemoteMethodRegistry reg = rmiCx.getMethods();
		reg.add(rmiMethodReadMem);
		reg.add(rmiMethodWriteMem);
	}

	protected TraceObject addMemoryRegion(TraceObjectManager objs, Lifespan lifespan,
			AddressRange range, String name, String flags) {
		String pathStr =
			"Processes[1].Memory[0x%08x:%s]".formatted(range.getMinAddress().getOffset(), name);
		TraceObject regionText = objs.createObject(KeyPath.parse(pathStr));
		regionText.setAttribute(lifespan, "_range", range);
		regionText.setAttribute(lifespan, "_readable", flags.contains("r"));
		regionText.setAttribute(lifespan, "_writable", flags.contains("w"));
		regionText.setAttribute(lifespan, "_executable", flags.contains("x"));
		regionText.insert(lifespan, ConflictResolution.DENY);

		return regionText;
	}

	protected void handleReadMemInvocation(TraceObject process, AddressRange range,
			Callable<Object> action) throws Exception {
		assertEquals(Map.ofEntries(
			Map.entry("process", process),
			Map.entry("range", range)),
			rmiMethodReadMem.expect());
		rmiMethodReadMem.result(action.call());
	}

	protected void handleReadMemInvocation(TraceObject process, AddressRange range)
			throws Exception {
		handleReadMemInvocation(process, range, () -> {
			try (Transaction tx = tb.startTransaction()) {
				tb.trace.getMemoryManager().setState(0, range, TraceMemoryState.KNOWN);
			}
			return null;
		});
	}

	protected void flushMemoryReadInvocations(Supplier<CompletableFuture<?>> taskSupplier,
			TraceObject process, AddressRange range) throws Exception {
		while (!taskSupplier.get().isDone()) {
			while (!rmiMethodReadMem.argQueue().isEmpty()) {
				handleReadMemInvocation(process, range, () -> null);
			}
		}
	}

	protected void handleAtLeastOneMemReadInv(Supplier<CompletableFuture<?>> taskSupplier,
			TraceObject process, AddressRange range) throws Exception {
		handleReadMemInvocation(process, range);
		flushMemoryReadInvocations(taskSupplier, process, range);
	}

	public record Bytes(byte[] bytes) {
		public static Object wrapMaybe(Object v) {
			return switch (v) {
				case byte[] b -> new Bytes(b);
				default -> v;
			};
		}

		public static Map<String, Object> wrapVals(Map<String, Object> map) {
			return map.entrySet()
					.stream()
					.collect(Collectors.toMap(Entry::getKey, e -> Bytes.wrapMaybe(e.getValue())));
		}

		public Bytes(int... values) {
			this(ArrayUtils.toPrimitive(
				IntStream.of(values).mapToObj(i -> (byte) i).toArray(Byte[]::new)));
		}

		@Override
		public final boolean equals(Object o) {
			return o instanceof Bytes that && Arrays.equals(this.bytes, that.bytes);
		}

		@Override
		public String toString() {
			return "Bytes[" + NumericUtilities.convertBytesToString(bytes) + "]";
		}

		public ByteBuffer buf() {
			return ByteBuffer.wrap(bytes);
		}
	}

	protected void handleWriteMemInvocation(TraceObject process, Address start, Bytes data)
			throws Exception {
		assertEquals(Map.ofEntries(
			Map.entry("process", tb.obj("Processes[1]")),
			Map.entry("start", start),
			Map.entry("data", data)),
			Bytes.wrapVals(rmiMethodWriteMem.expect()));
		rmiMethodWriteMem.result(null);
	}

	protected TraceObject ensureBreakpointContainer(TraceObjectManager objs) {
		try (Transaction tx = tb.startTransaction()) {
			return objs.createObject(KeyPath.parse("Processes[1].Breakpoints"));
		}
	}

	protected TraceObject findAndCreateFreeBreakpointSpec(TraceObjectManager objs, Integer id) {
		KeyPath brkConPath = KeyPath.parse("Processes[1].Breakpoints");
		if (id != null) {
			KeyPath path = brkConPath.index(id);
			TraceObject exists = objs.getObjectByCanonicalPath(path);
			if (exists != null) {
				return exists;
			}
			return objs.createObject(path);
		}
		for (int i = 1; i < 10; i++) {
			KeyPath path = brkConPath.index(i);
			TraceObject exists = objs.getObjectByCanonicalPath(path);
			if (exists == null) {
				return objs.createObject(path);
			}
		}
		throw new AssertionError("More than 10 breakpoints for a test?");
	}

	protected TraceObject addBreakpointAndLoc(TraceObjectManager objs, Lifespan lifespan,
			AddressRange range, Set<TraceBreakpointKind> kinds, Integer id) {
		try (Transaction tx = objs.getTrace().openTransaction("Add breakpoint")) {
			TraceObject spec = findAndCreateFreeBreakpointSpec(objs, id);

			spec.setAttribute(lifespan, "_kinds", TraceBreakpointKindSet.encode(kinds));
			spec.setAttribute(lifespan, "_expr", "*0x" + range.getMinAddress());
			spec.setAttribute(lifespan, "_enabled", true);
			spec.insert(lifespan, ConflictResolution.DENY);

			KeyPath specPath = spec.getCanonicalPath();
			TraceObject loc = objs.createObject(specPath.index(0));
			loc.setAttribute(lifespan, "_display", specPath.index());
			loc.setAttribute(lifespan, "_range", range);
			loc.insert(lifespan, ConflictResolution.DENY);
			return spec;
		}
	}

	protected TraceObject addBreakpointAndLoc(TraceObjectManager objs, Lifespan lifespan,
			AddressRange range, Set<TraceBreakpointKind> kinds) {
		return addBreakpointAndLoc(objs, lifespan, range, kinds, null);
	}
}
