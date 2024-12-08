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
package ghidra.debug.flatapi;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.services.*;
import ghidra.debug.api.control.ControlMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.thread.TraceThread;

public abstract class AbstractFlatDebuggerAPITest<API extends FlatDebuggerAPI>
		extends AbstractGhidraHeadedDebuggerIntegrationTest {

	protected DebuggerLogicalBreakpointService breakpointService;
	protected DebuggerStaticMappingService mappingService;
	protected DebuggerEmulationService emulationService;
	protected DebuggerListingService listingService;
	protected DebuggerControlService editingService;
	protected API api;

	protected abstract API newFlatAPI();

	@Before
	public void setUpFlatAPITest() throws Throwable {
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		mappingService = tool.getService(DebuggerStaticMappingService.class);
		emulationService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
		listingService = addPlugin(tool, DebuggerListingPlugin.class);
		editingService = addPlugin(tool, DebuggerControlServicePlugin.class);
		api = newFlatAPI();

		// TODO: This seems to hold up the task manager.
		waitForComponentProvider(DebuggerListingProvider.class).setAutoDisassemble(false);
	}

	@Override
	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		super.createProgram(lang, cSpec);
		api.getState().setCurrentProgram(program);
	}

	protected TraceThread createTraceWithThreadAndStack(boolean open) throws Throwable {
		if (open) {
			createAndOpenTrace();
		}
		else {
			createTrace();
		}
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.setDepth(3, true);
		}
		waitForSwing();
		return thread;
	}

	protected void createTraceWithBinText() throws Throwable {
		createAndOpenTrace();

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager mm = tb.trace.getMemoryManager();
			mm.createRegion("Memory[bin.text]", 0, tb.range(0x00400000, 0x0040ffff),
				Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

			mm.putBytes(0, tb.addr(0x00400000), tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
		}
		traceManager.activateTrace(tb.trace);
		waitForSwing();
	}

	protected void createMappedTraceAndProgram() throws Throwable {
		createAndOpenTrace();
		createProgramFromTrace();

		intoProject(program);
		intoProject(tb.trace);

		programManager.openProgram(program);
		traceManager.activateTrace(tb.trace);

		try (Transaction tx = program.openTransaction("add block")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 4096, (byte) 0,
						monitor, false);
		}

		CompletableFuture<Void> changesSettled;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.createRegion("Memory[bin.text]", 0, tb.range(0x00400000, 0x00400fff),
						Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));
			changesSettled = mappingService.changesSettled();
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.nowOn(0), true);
		}
		waitForSwing();
		waitOn(changesSettled);
	}

	protected Address createEmulatableProgram() throws Throwable {
		createProgram();
		programManager.openProgram(program);

		Address entry = addr(program, 0x00400000);
		try (Transaction start = program.openTransaction("init")) {
			program.getMemory()
					.createInitializedBlock(".text", entry, 4096, (byte) 0,
						monitor, false);
			Assembler asm = Assemblers.getAssembler(program);
			asm.assemble(entry, "imm r0,#123");
		}

		// Emulate launch will create a static mapping
		intoProject(program);

		return entry;
	}

	@Test
	public void testReadMemoryBuffer() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		byte[] data = new byte[1024];
		assertEquals(1024, api.readMemory(tb.addr(0x00400000), data, monitor));
		assertArrayEquals(new byte[1024], data);
	}

	@Test
	public void testReadMemoryLength() throws Throwable {
		createAndOpenTrace();
		traceManager.activateTrace(tb.trace);

		byte[] data = api.readMemory(tb.addr(0x00400000), 1024, monitor);
		assertArrayEquals(new byte[1024], data);
	}

	@Test
	public void testReadRegister() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0), api.readRegister("r0"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testReadRegisterInvalidNameErr() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		api.readRegister("THERE_IS_NO_SUCH_REGISTER");
	}

	@Test
	public void testReadRegisters() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);
		waitForSwing();

		Register r0 = tb.language.getRegister("r0");
		Register r1 = tb.language.getRegister("r1");
		assertEquals(List.of(
			new RegisterValue(r0),
			new RegisterValue(r1)),
			api.readRegistersNamed(List.of("r0", "r1")));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testReadRegistersInvalidNameErr() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		traceManager.activateThread(thread);

		api.readRegistersNamed(Set.of("THERE_IS_NO_SUCH_REGISTER"));
	}

	@Test
	public void testWriteMemoryGivenContext() throws Throwable {
		createTraceWithBinText();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		assertTrue(api.writeMemory(tb.trace, 0, tb.addr(0x00400123), tb.arr(3, 2, 1)));
		ByteBuffer buf = ByteBuffer.allocate(3);
		assertEquals(3, tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400123), buf));
		assertArrayEquals(tb.arr(3, 2, 1), buf.array());
	}

	@Test
	public void testWriteMemoryCurrentContext() throws Throwable {
		createTraceWithBinText();
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		assertTrue(api.writeMemory(tb.addr(0x00400123), tb.arr(3, 2, 1)));
		ByteBuffer buf = ByteBuffer.allocate(3);
		assertEquals(3, tb.trace.getMemoryManager().getBytes(0, tb.addr(0x00400123), buf));
		assertArrayEquals(tb.arr(3, 2, 1), buf.array());
	}

	@Test
	public void testWriteRegisterGivenContext() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(api.writeRegister(thread, 0, 0, "r0", BigInteger.valueOf(0x0102030405060708L)));
		DBTraceMemorySpace regs =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertNotNull(regs);
		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			regs.getValue(0, r0));
	}

	@Test
	public void testWriteRegisterCurrentContext() throws Throwable {
		TraceThread thread = createTraceWithThreadAndStack(true);
		editingService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);
		traceManager.activateThread(thread);
		waitForSwing();

		assertTrue(api.writeRegister("r0", BigInteger.valueOf(0x0102030405060708L)));
		DBTraceMemorySpace regs =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertNotNull(regs);
		Register r0 = tb.language.getRegister("r0");
		assertEquals(new RegisterValue(r0, BigInteger.valueOf(0x0102030405060708L)),
			regs.getValue(0, r0));
	}

	protected void createProgramWithText() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		waitForSwing();

		try (Transaction tx = program.openTransaction("Add block")) {
			program.getMemory()
					.createInitializedBlock(
						".text", addr(program, 0x00400000), 1024, (byte) 0, monitor, false);
		}
	}

	protected void createProgramWithBreakpoint() throws Throwable {
		createProgramWithText();

		CompletableFuture<Void> changesSettled = breakpointService.changesSettled();
		waitOn(breakpointService.placeBreakpointAt(program, addr(program, 0x00400000), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE), "name"));
		waitForSwing();
		waitOn(changesSettled);
	}
}
