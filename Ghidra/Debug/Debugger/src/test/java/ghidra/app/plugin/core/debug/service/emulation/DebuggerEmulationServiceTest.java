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
package ghidra.app.plugin.core.debug.service.emulation;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformOpinion;
import ghidra.app.plugin.core.debug.service.platform.DebuggerPlatformServicePlugin;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.pcode.exec.DecodePcodeExecutionException;
import ghidra.pcode.exec.InterruptPcodeExecutionException;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.Scheduler;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerEmulationServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerEmulationServicePlugin emulationPlugin;
	protected CodeBrowserPlugin codeBrowser;

	@Before
	public void setUpEmulationServiceTest() throws Exception {
		emulationPlugin = addPlugin(tool, DebuggerEmulationServicePlugin.class);
		// TODO: Action enablement doesn't work without CodeBrowser???
		// Probably missing some contextChanged, but I have no provider!
		// I need it for GoTo anyway
		codeBrowser = addPlugin(tool, CodeBrowserPlugin.class);
	}

	@Test
	public void testPureEmulation() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			memory.createInitializedBlock(".data", addr(program, 0x00600000), 0x1000, (byte) 0,
				TaskMonitor.DUMMY, false);
			asm.assemble(addrText, "mov r0, r1");
			program.getProgramContext()
					.setValue(regR1, addrText, addrText, new BigInteger("1234", 16));
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		assertTrue(emulationPlugin.actionEmulateProgram.isEnabled());
		performAction(emulationPlugin.actionEmulateProgram);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertEquals(new BigInteger("00400000", 16),
			regs.getViewValue(0, regPC).getUnsignedValue());
		assertEquals(new BigInteger("0000", 16), regs.getViewValue(0, regR0).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16), regs.getViewValue(0, regR1).getUnsignedValue());

		long scratch =
			emulationPlugin.emulate(trace, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);

		assertEquals(new BigInteger("00400002", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
	}

	@Test
	public void testPureEmulationHarvard() throws Exception {
		Language toyHv = getLanguageService().getLanguage(new LanguageID("Toy:BE:64:harvard"));
		createProgram(toyHv);
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		AddressSpace codeSpace = program.getLanguage().getDefaultSpace();
		AddressSpace dataSpace = program.getLanguage().getDefaultDataSpace();
		Address addrText = codeSpace.getAddress(0x00000400);
		Address addrData = dataSpace.getAddress(0x00000400);
		assertNotEquals(addrText, addrData);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			MemoryBlock blockData = memory.createInitializedBlock(".data", addrData, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			asm.assemble(addrText, "load r0, [r1]");
			program.getProgramContext()
					.setValue(regR1, addrText, addrText, new BigInteger("00000400", 16));
			blockData.putBytes(addrData, new byte[] { 0, 0, 0, 0, 0, 0, 0x12, 0x34 });
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		assertTrue(emulationPlugin.actionEmulateProgram.isEnabled());
		performAction(emulationPlugin.actionEmulateProgram);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertEquals(new BigInteger("00000400", 16),
			regs.getViewValue(0, regPC).getUnsignedValue());
		assertEquals(new BigInteger("0000", 16), regs.getViewValue(0, regR0).getUnsignedValue());
		assertEquals(new BigInteger("00000400", 16),
			regs.getViewValue(0, regR1).getUnsignedValue());

		long scratch =
			emulationPlugin.emulate(trace, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);

		assertEquals(new BigInteger("00000402", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("00000400", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
	}

	@Test
	public void testPureEmulationMemoryMappedPC_NonByteAddressable() throws Exception {
		Language pic33F =
			getLanguageService().getLanguage(new LanguageID("dsPIC33F:LE:24:default"));
		createProgram(pic33F);
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		AddressSpace codeSpace = program.getLanguage().getDefaultSpace();
		AddressSpace dataSpace = program.getLanguage().getDefaultDataSpace();
		Address addrText = codeSpace.getAddress(0x00000100, true);
		Address addrData = dataSpace.getAddress(0x00000800, true);
		assertNotEquals(addrText, addrData);
		Register regPC = program.getRegister("PC");
		Register regW0 = program.getRegister("W0");
		Register regW1 = program.getRegister("W1");
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			MemoryBlock blockData = memory.createInitializedBlock(".data", addrData, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			asm.assemble(addrText, "mov.w [W1], W0");
			program.getProgramContext()
					.setValue(regW1, addrText, addrText, new BigInteger("0800", 16));
			blockData.putBytes(addrData, new byte[] { 0x34, 0x12 }); // LE
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		assertTrue(emulationPlugin.actionEmulateProgram.isEnabled());
		performAction(emulationPlugin.actionEmulateProgram);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceMemoryManager mem = trace.getMemoryManager();
		assertEquals(new BigInteger("000100", 16),
			mem.getViewValue(0, regPC).getUnsignedValue());
		assertEquals(new BigInteger("0000", 16),
			mem.getViewValue(0, regW0).getUnsignedValue());
		assertEquals(new BigInteger("0800", 16),
			mem.getViewValue(0, regW1).getUnsignedValue());

		long scratch =
			emulationPlugin.emulate(trace, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);

		assertEquals(new BigInteger("000102", 16),
			mem.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			mem.getViewValue(scratch, regW0).getUnsignedValue());
		assertEquals(new BigInteger("0800", 16),
			mem.getViewValue(scratch, regW1).getUnsignedValue());
	}

	@Test
	public void testPureEmulationRelocated() throws Throwable {
		createAndOpenTrace("x86:LE:64:default");
		createProgramFromTrace();

		intoProject(program);
		intoProject(tb.trace);

		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Address addrData = addr(program, 0x00600000);
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock("text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			memory.createInitializedBlock(".data", addrData, 0x1000, (byte) 0, TaskMonitor.DUMMY,
				false);

			// NOTE: qword ptr [0x00600800] is RIP-relative
			asm.assemble(addrText, "MOV RAX, qword ptr [0x00600800]");
			memory.setLong(addr(program, 0x00600800), 0xdeadbeefcafebabeL);
		}

		programManager.openProgram(program);
		waitForSwing();

		DebuggerStaticMappingService mappings =
			tool.getService(DebuggerStaticMappingService.class);
		CompletableFuture<Void> settled;
		TraceThread thread;
		TraceMemorySpace regs;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			regs = tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(program.getLanguage().getProgramCounter(),
				BigInteger.valueOf(0x55550000)));
			settled = mappings.changesSettled();
			mappings.addMapping(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				tb.addr(0x55550000)), new ProgramLocation(program, addrText), 0x1000, false);
			mappings.addMapping(new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0),
				tb.addr(0x55750000)), new ProgramLocation(program, addrData), 0x1000, false);
		}
		waitForSwing();
		waitOn(settled);

		long scratch =
			emulationPlugin.emulate(tb.trace, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);

		assertEquals("deadbeefcafebabe",
			regs.getViewValue(scratch, tb.reg("RAX")).getUnsignedValue().toString(16));
	}

	@Test
	public void testEmulationGuest() throws Throwable {
		DebuggerPlatformServicePlugin platformPlugin =
			addPlugin(tool, DebuggerPlatformServicePlugin.class);

		createTrace();

		Language x64 = getSLEIGH_X86_64_LANGUAGE();
		Assembler asm = Assemblers.getAssembler(x64);
		AssemblyBuffer buf = new AssemblyBuffer(asm, tb.addr(x64, 0x00400000));
		TraceMemoryManager mem = tb.trace.getMemoryManager();
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			buf.assemble("MOV RAX, qword ptr [0x00600800]");
			mem.putBytes(0, tb.addr(0x00400000), ByteBuffer.wrap(buf.getBytes()));
			mem.putBytes(0, tb.addr(0x00600800),
				ByteBuffer.wrap(Utils.longToBytes(0xdeadbeefcafebabeL, 8, false)));
		}
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		CompilerSpec x64Default = x64.getDefaultCompilerSpec();
		DebuggerPlatformMapper mapper =
			DebuggerPlatformOpinion.queryOpinions(tb.trace, null, 0, true)
					.stream()
					.filter(o -> x64.getLanguageID().equals(o.getLanguageID()))
					.filter(o -> x64Default.getCompilerSpecID().equals(o.getCompilerSpecID()))
					.findAny()
					.orElse(null)
					.take(tool, tb.trace);
		platformPlugin.setCurrentMapperFor(tb.trace, mapper, 0);
		waitForSwing();

		waitForPass(() -> assertEquals(x64, traceManager.getCurrentPlatform().getLanguage()));
		TracePlatform platform = traceManager.getCurrentPlatform();

		try (Transaction tx = tb.startTransaction()) {
			tb.exec(platform, 0, thread, 0, "RIP = 0x00400000;");
		}

		long scratch =
			emulationPlugin.emulate(platform, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);
		TraceMemorySpace regs = mem.getMemoryRegisterSpace(thread, false);
		assertEquals("deadbeefcafebabe",
			regs.getViewValue(platform, scratch, tb.reg(platform, "RAX"))
					.getUnsignedValue()
					.toString(16));
	}

	@Test
	public void testInterruptOnDecodeUninitialized() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");

		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			asm.assemble(addrText,
				"br 0x003ffffe");
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		EmulationResult result = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			TraceSchedule.snap(0), TaskMonitor.DUMMY, Scheduler.oneThread(thread));

		assertEquals(TraceSchedule.parse("0:t0-1"), result.schedule());
		assertTrue(result.error() instanceof DecodePcodeExecutionException);

		long scratch = result.snapshot();
		assertEquals(new BigInteger("003ffffe", 16), regs.getViewValue(scratch, regPC).getUnsignedValue());
	}

	@Test
	public void testExecutionBreakpoint() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		Register regR2 = program.getRegister("r2");
		Address addrI2;
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			InstructionIterator ii = asm.assemble(addrText,
				"mov r0, r1",
				"mov r2, r0");
			ii.next();
			addrI2 = ii.next().getMinAddress();
			program.getProgramContext()
					.setValue(regR1, addrText, addrText, new BigInteger("1234", 16));
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), addrI2, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
		}

		EmulationResult result = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			TraceSchedule.snap(0), TaskMonitor.DUMMY, Scheduler.oneThread(thread));

		assertEquals(TraceSchedule.parse("0:t0-1"), result.schedule());
		assertTrue(result.error() instanceof InterruptPcodeExecutionException);

		long scratch = result.snapshot();

		assertEquals(new BigInteger("00400002", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
		assertEquals(new BigInteger("0", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());
	}

	@Test
	public void testRunAfterExecutionBreakpoint() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Address addrI1;
		Address addrI2;
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			InstructionIterator ii = asm.assemble(addrText,
				"mov r0, r0",
				"mov r0, r1",
				"mov r2, r0");
			ii.next(); // addrText
			addrI1 = ii.next().getMinAddress();
			addrI2 = ii.next().getMinAddress();
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());

		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), addrText, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
			trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[1]", Lifespan.nowOn(0), addrI1, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
			trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[2]", Lifespan.nowOn(0), addrI2, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
		}

		// This is already testing if the one set at the entry is ignored
		EmulationResult result1 = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			TraceSchedule.snap(0), monitor, Scheduler.oneThread(thread));
		assertEquals(TraceSchedule.parse("0:t0-1"), result1.schedule());
		assertTrue(result1.error() instanceof InterruptPcodeExecutionException);

		// This will test if the one just hit gets ignored
		EmulationResult result2 = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			result1.schedule(), monitor, Scheduler.oneThread(thread));
		assertEquals(TraceSchedule.parse("0:t0-2"), result2.schedule());
		assertTrue(result1.error() instanceof InterruptPcodeExecutionException);
	}

	@Test
	public void testExecutionInjection() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		Register regR2 = program.getRegister("r2");
		Address addrI2;
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			InstructionIterator ii = asm.assemble(addrText,
				"mov r0, r1",
				"mov r2, r0");
			ii.next();
			addrI2 = ii.next().getMinAddress();
			program.getProgramContext()
					.setValue(regR1, addrText, addrText, new BigInteger("1234", 16));
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			TraceBreakpoint tb = trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), addrI2, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
			tb.setEmuSleigh("""
					r1 = 0x5678;
					emu_swi();
					emu_exec_decoded();
					""");
		}

		EmulationResult result = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			TraceSchedule.snap(0), TaskMonitor.DUMMY, Scheduler.oneThread(thread));

		assertEquals(TraceSchedule.parse("0:t0-1.t0-2"), result.schedule());
		assertTrue(result.error() instanceof InterruptPcodeExecutionException);

		long scratch = result.snapshot();

		assertEquals(new BigInteger("00400002", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("5678", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
		assertEquals(new BigInteger("0", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());
	}

	@Test
	public void testAccessBreakpoint() throws Exception {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		Register regR2 = program.getRegister("r2");
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			asm.assemble(addrText,
				"store [r0], r1",
				"load r2, [r0]");
			ProgramContext ctx = program.getProgramContext();
			ctx.setValue(regR0, addrText, addrText, new BigInteger("1234", 16));
			ctx.setValue(regR1, addrText, addrText, new BigInteger("5678", 16));
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemoryManager mem = trace.getMemoryManager();
		TraceMemorySpace regs = mem.getMemoryRegisterSpace(thread, false);

		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), addr(trace, 0x1234),
						Set.of(thread), Set.of(TraceBreakpointKind.READ), true, "test");
		}

		EmulationResult result = emulationPlugin.run(trace.getPlatformManager().getHostPlatform(),
			TraceSchedule.snap(0), TaskMonitor.DUMMY, Scheduler.oneThread(thread));

		assertEquals(TraceSchedule.parse("0:t0-1"), result.schedule());
		assertTrue(result.error() instanceof InterruptPcodeExecutionException);

		long scratch = result.snapshot();

		assertEquals(new BigInteger("00400002", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("5678", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
		byte[] arr = new byte[8];
		mem.getViewBytes(scratch, addr(trace, 0x1234), ByteBuffer.wrap(arr));
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0x56, 0x78 }, arr);
		assertEquals(new BigInteger("0", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());
	}

	@Test
	public void testCacheInvalidation() throws Throwable {
		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regR0 = program.getRegister("r0");
		Register regR2 = program.getRegister("r2");
		Address addrI2;
		try (Transaction tx = program.openTransaction("Initialize")) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			InstructionIterator ii = asm.assemble(addrText,
				"mov r1, r0",
				"mov r2, r1");
			ii.next();
			addrI2 = ii.next().getMinAddress();
			program.getProgramContext()
					.setValue(regR0, addrText, addrText, new BigInteger("1234", 16));
		}

		programManager.openProgram(program);
		waitForSwing();
		codeBrowser.goTo(new ProgramLocation(program, addrText));
		waitForSwing();

		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionEmulateProgram, true);

		DebuggerCoordinates current = traceManager.getCurrent();
		Trace trace = current.getTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);

		// Step as written to fill the cache
		waitOn(traceManager.activateAndNotify(current.time(TraceSchedule.parse("0:t0-1")),
			ActivationCause.USER, false));
		waitForSwing();
		waitOn(traceManager.activateAndNotify(current.time(TraceSchedule.parse("0:t0-2")),
			ActivationCause.USER, false));
		waitForSwing();
		long scratch = traceManager.getCurrentView().getSnap();

		// Sanity check
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());

		// Inject some logic that would require a cache refresh to materialize
		try (Transaction tx = trace.openTransaction("Add breakpoint")) {
			TraceBreakpoint tb = trace.getBreakpointManager()
					.addBreakpoint("Breakpoints[0]", Lifespan.nowOn(0), addrI2, Set.of(thread),
						Set.of(TraceBreakpointKind.SW_EXECUTE), true, "test");
			tb.setEmuSleigh("""
					r1 = 0x5678;
					emu_exec_decoded();
					""");
		}

		// Check the cache is still valid
		waitOn(traceManager.activateAndNotify(current.time(TraceSchedule.parse("0:t0-1")),
			ActivationCause.USER, false));
		waitForSwing();
		waitOn(traceManager.activateAndNotify(current.time(TraceSchedule.parse("0:t0-2")),
			ActivationCause.USER, false));
		waitForSwing();
		assertEquals(scratch, traceManager.getCurrentView().getSnap());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());

		// Invalidate the cache. View should update immediately
		performEnabledAction(codeBrowser.getProvider(), emulationPlugin.actionInvalidateCache,
			true);
		waitForTasks();
		assertEquals(new BigInteger("5678", 16),
			regs.getViewValue(scratch, regR2).getUnsignedValue());
	}
}
