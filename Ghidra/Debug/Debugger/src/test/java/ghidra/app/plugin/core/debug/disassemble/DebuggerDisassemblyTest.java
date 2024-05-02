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
package ghidra.app.plugin.core.debug.disassemble;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.action.DockingActionIf;
import generic.Unique;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.assembler.AssemblerPluginTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.action.LoadEmulatorAutoReadMemorySpec;
import ghidra.app.plugin.core.debug.gui.listing.*;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.ProgramEmulationUtils;
import ghidra.app.plugin.core.debug.service.platform.DebuggerPlatformServicePlugin;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.debug.api.control.ControlMode;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.listing.DBTraceInstruction;
import ghidra.trace.database.listing.DBTraceInstructionsMemoryView;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.stack.DBTraceStackManager;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.stack.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.task.TaskMonitor;

public class DebuggerDisassemblyTest extends AbstractGhidraHeadedDebuggerTest {
	protected DebuggerDisassemblerPlugin disassemblerPlugin;
	protected DebuggerPlatformService platformService;
	protected DebuggerListingProvider listingProvider;
	protected SchemaContext ctx;

	@Before
	public void setUpDisassemblyTest() throws Exception {
		ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
				        <attribute name='Targets' schema='TargetContainer' />
				    </schema>
				    <schema name='TargetContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='ONCE'>
				        <element schema='Target' />
				    </schema>
				    <schema name='Target' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Process' />
				        <interface name='Aggregate' />
				        <attribute name='Environment' schema='Environment' />
				        <attribute name='Memory' schema='Memory' />
				        <attribute name='Threads' schema='ThreadContainer' />
				    </schema>
				    <schema name='Environment' elementResync='NEVER'
				            attributeResync='NEVER'>"
				        <interface name='Environment' />
				    </schema>
				    <schema name='Memory' canonical='yes' elementResync='NEVER'
				            attributeResync='NEVER'>
				        <element schema='MemoryRegion' />"
				    </schema>
				    <schema name='MemoryRegion' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='MemoryRegion' />
				    </schema>"
				    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
				            attributeResync='NEVER'>
				        <element schema='Thread' />
				    </schema>
				    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='Thread' />
				        <interface name='Aggregate' />
				        <attribute name='Stack' schema='Stack' />
				    </schema>
				    <schema name='Stack' canonical='yes' elementResync='NEVER'
				            attributeResync='NEVER'>
				        <interface name='Stack' />
				        <interface name='Aggregate' />
				        <element schema='Frame' />
				    </schema>
				    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='StackFrame' />
				        <interface name='Aggregate' />
				        <attribute name='Registers' schema='RegisterContainer' />
				    </schema>
				    <schema name='RegisterContainer' elementResync='NEVER' attributeResync='NEVER'>
				        <interface name='RegisterContainer' />
				        <element schema='Register' />
				    </schema>
				    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
				       <interface name='Register' />
				    </schema>
				</context>""");

		addPlugin(tool, DebuggerListingPlugin.class);
		platformService = addPlugin(tool, DebuggerPlatformServicePlugin.class);
		disassemblerPlugin = addPlugin(tool, DebuggerDisassemblerPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);

		// TODO: Maybe this shouldn't be the default for these tests?
		listingProvider.setAutoDisassemble(false);
	}

	protected void assertMnemonic(String expected, Instruction instruction) {
		assertNotNull(instruction);
		assertEquals(expected, instruction.getMnemonicString());
	}

	protected void enableAutoDisassembly() throws Throwable {
		listingProvider.setAutoDisassemble(true);
	}

	protected void enableLoadEmulator() throws Throwable {
		runSwing(() -> listingProvider.setAutoReadMemorySpec(new LoadEmulatorAutoReadMemorySpec()));
	}

	protected DebuggerListingActionContext createActionContext(Address start, int len) {
		TraceProgramView view = tb.trace.getProgramView();
		ProgramSelection sel = new ProgramSelection(start, start.addWrap(len - 1));
		return new DebuggerListingActionContext(listingProvider, new ProgramLocation(view, start),
			sel, null);
	}

	protected TraceObjectThread createPolyglotTrace(String arch, long offset,
			Supplier<ByteBuffer> byteSupplier) throws Exception {
		return createPolyglotTrace(arch, offset, byteSupplier, true);
	}

	protected TraceObjectThread createPolyglotTrace(String arch, long offset,
			Supplier<ByteBuffer> byteSupplier, boolean pcInStack) throws Exception {
		createAndOpenTrace("DATA:BE:64:default");

		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (Transaction tx = tb.startTransaction()) {
			objects.createRootObject(ctx.getSchema(new SchemaName("Session")));
			DBTraceObject env =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Environment"));
			assertEquals(ctx.getSchema(new SchemaName("Environment")), env.getTargetSchema());
			Lifespan zeroOn = Lifespan.nowOn(0);
			env.insert(zeroOn, ConflictResolution.DENY);
			env.setAttribute(zeroOn, TargetEnvironment.DEBUGGER_ATTRIBUTE_NAME, "test");
			env.setAttribute(zeroOn, TargetEnvironment.ARCH_ATTRIBUTE_NAME, arch);

			DBTraceObject objBinText =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Memory[bin:.text]"));
			TraceObjectMemoryRegion binText =
				objBinText.queryInterface(TraceObjectMemoryRegion.class);
			binText.addFlags(zeroOn, Set.of(TraceMemoryFlag.EXECUTE));
			binText.setRange(zeroOn, tb.range(offset, offset + 0xffff));
			// TODO: Why doesn't setRange work after insert?
			objBinText.insert(zeroOn, ConflictResolution.DENY);

			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			if (pcInStack) {
				DBTraceObject objFrame = objects
						.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0]"));
				objFrame.insert(zeroOn, ConflictResolution.DENY);
				TraceObjectStackFrame frame = objFrame.queryInterface(TraceObjectStackFrame.class);
				frame.setProgramCounter(zeroOn, tb.addr(offset));
			}
			else {
				objects.createObject(
					TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0].Registers"))
						.insert(zeroOn, ConflictResolution.DENY);
				TraceObjectThread thread = objects
						.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Targets[0].Threads[0]"))
						.queryInterface(TraceObjectThread.class);
				traceManager.activateThread(thread);
				DBTraceMemorySpace regs =
					Objects.requireNonNull(memory.getMemoryRegisterSpace(thread, true));
				TraceGuestPlatform platform =
					Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms());
				Register regPc = platform.getLanguage().getProgramCounter();
				regs.setValue(platform, 0, new RegisterValue(regPc, BigInteger.valueOf(offset)));
			}

			ByteBuffer bytes = byteSupplier.get();
			assertEquals(bytes.remaining(), memory.putBytes(0, tb.addr(offset), bytes));
		}
		TraceObjectThread thread =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Targets[0].Threads[0]"))
					.queryInterface(TraceObjectThread.class);
		traceManager.activateThread(thread);
		return thread;
	}

	protected void setLegacyProgramCounterInStack(long offset, TraceThread thread, long snap) {
		try (Transaction tx = tb.startTransaction()) {
			DBTraceStackManager manager = tb.trace.getStackManager();
			TraceStack stack = manager.getStack(thread, snap, true);
			TraceStackFrame frame = stack.getFrame(0, true);
			frame.setProgramCounter(Lifespan.nowOn(snap), tb.addr(offset));
		}
	}

	protected void setLegacyProgramCounterInRegs(long offset, TraceThread thread, long snap) {
		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			DBTraceMemorySpace regs = memory.getMemoryRegisterSpace(thread, true);
			Register pc = tb.language.getProgramCounter();
			regs.setValue(0, new RegisterValue(pc, BigInteger.valueOf(offset)));
		}
	}

	protected void createLegacyTrace(String langID, long offset, Supplier<ByteBuffer> byteSupplier)
			throws Throwable {
		createAndOpenTrace(langID);

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion("Memory[bin:.text]", 0, tb.range(offset, offset + 0xffff),
				Set.of(TraceMemoryFlag.EXECUTE, TraceMemoryFlag.READ));
			ByteBuffer bytes = byteSupplier.get();
			assertEquals(bytes.remaining(), memory.putBytes(0, tb.addr(offset), bytes));
		}
		traceManager.activateTrace(tb.trace);
	}

	@Test
	public void testAutoDisassembleX8664() throws Throwable {
		enableAutoDisassembly();
		createPolyglotTrace("x86-64", 0x00400000, () -> tb.buf(0x90, 0x90, 0x90));

		getSLEIGH_X86_64_LANGUAGE(); // So that the load isn't charged against the time-out
		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400000)));
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400001)));
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400002)));
			assertNull(instructions.getAt(0, tb.addr(0x00400003)));
		});
	}

	@Test
	public void testAutoDisasembleReDisasembleX8664Offcut() throws Throwable {
		enableAutoDisassembly();
		createLegacyTrace("x86:LE:64:default", 0x00400000, () -> tb.buf(0xeb, 0xff, 0xc0));

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread 1", 0);
		}

		setLegacyProgramCounterInStack(0x00400000, thread, 0);

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertMnemonic("JMP", instructions.getAt(0, tb.addr(0x00400000)));
			/**
			 * Depending on preference for branch or fall-through, the disassembler may or may not
			 * proceed to the following instructions. I don't really care, since the test is the the
			 * JMP gets deleted after the update to PC.
			 */
		});

		// The jump will advance one byte. Just simulate that by updating the stack and/or regs
		setLegacyProgramCounterInStack(0x00400001, thread, 1);
		traceManager.activateSnap(1);

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertNull(instructions.getAt(1, tb.addr(0x00400000)));
			assertMnemonic("INC", instructions.getAt(1, tb.addr(0x00400001)));
			assertNull(instructions.getAt(1, tb.addr(0x00400003)));
		});
	}

	@Test
	public void testAutoDisassembleReDisassembleX8664OffcutByEmulation() throws Throwable {
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
		enableAutoDisassembly();
		createLegacyTrace("x86:LE:64:default", 0x00400000, () -> tb.buf(0xeb, 0xff, 0xc0));

		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Thread 1", 0);
		}

		setLegacyProgramCounterInRegs(0x00400000, thread, 0);

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertMnemonic("JMP", instructions.getAt(0, tb.addr(0x00400000)));
			/**
			 * Depending on preference for branch or fall-through, the disassembler may or may not
			 * proceed to the following instructions. I don't really care, since the test is the the
			 * JMP gets deleted after the update to PC.
			 */
		});

		TraceSchedule schedule = TraceSchedule.snap(0).steppedForward(thread, 1);
		// Pre-load the cache, so I don't have to wait for background async emulation
		long viewSnap = emuService.emulate(tb.trace, schedule, monitor);
		traceManager.activateTime(schedule);
		waitForSwing();
		assertEquals(viewSnap, traceManager.getCurrentView().getSnap());

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertNull(instructions.getAt(viewSnap, tb.addr(0x00400000)));
			assertMnemonic("INC", instructions.getAt(viewSnap, tb.addr(0x00400001)));
			assertNull(instructions.getAt(viewSnap, tb.addr(0x00400003)));
		});
	}

	@Test
	public void testAutoDisassembleReDisassembleX8664OffcutByProgEmu() throws Throwable {
		DebuggerEmulationService emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		createProgram(getSLEIGH_X86_64_LANGUAGE());
		Address start;
		try (Transaction tx = program.openTransaction("Load")) {
			start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00400000);
			program.getMemory()
					.createInitializedBlock(".text", start, new ByteArrayInputStream(arr("ebffc0")),
						3, monitor, false);
		}
		intoProject(program);

		useTrace(ProgramEmulationUtils.launchEmulationTrace(program, start, this));
		tb.trace.release(this);
		TraceThread thread = Unique.assertOne(tb.trace.getThreadManager().getAllThreads());

		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);

		enableLoadEmulator();
		enableAutoDisassembly();

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertMnemonic("JMP", instructions.getAt(0, tb.addr(0x00400000)));
			/**
			 * Depending on preference for branch or fall-through, the disassembler may or may not
			 * proceed to the following instructions. I don't really care, since the test is the the
			 * JMP gets deleted after the update to PC.
			 */
		});

		TraceSchedule schedule = TraceSchedule.snap(0).steppedForward(thread, 1);
		// Pre-load the cache, so I don't have to wait for background async emulation
		long viewSnap = emuService.emulate(tb.trace, schedule, monitor);
		traceManager.activateTime(schedule);
		waitForSwing();
		assertEquals(viewSnap, traceManager.getCurrentView().getSnap());

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertNull(instructions.getAt(viewSnap, tb.addr(0x00400000)));
			assertMnemonic("INC", instructions.getAt(viewSnap, tb.addr(0x00400001)));
			assertNull(instructions.getAt(viewSnap, tb.addr(0x00400003)));
		});
	}

	@Test
	public void testAutoDisassembleGuestX8664WithPcInRegs() throws Throwable {
		enableAutoDisassembly();
		getSLEIGH_X86_64_LANGUAGE(); // So that the platform is mapped promptly
		createPolyglotTrace("x86-64", 0x00400000, () -> tb.buf(0x90, 0x90, 0x90), false);

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400000)));
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400001)));
			assertMnemonic("NOP", instructions.getAt(0, tb.addr(0x00400002)));
			assertNull(instructions.getAt(0, tb.addr(0x00400003)));
		});
	}

	@Test
	public void testCurrentDisassembleActionHostArm() throws Throwable {
		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf(0x1e, 0xff, 0x2f, 0xe1));

		// Fabricate the cpsr so that ARM is used. Otherwise, it will assume Cortex-M, so THUMB
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			DBTraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(0, new RegisterValue(tb.language.getRegister("cpsr"), BigInteger.ZERO));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		ListingActionContext actionContext = createActionContext(start, 4);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(4, ins.getLength());
	}

	@Test
	public void testCurrentDisassembleActionHostThumb() throws Throwable {
		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf(0x70, 0x47));

		// Fabricate the cpsr so that THUMB is used, even though we could omit as in Cortex-M
		TraceThread thread;
		try (Transaction tx = tb.startTransaction()) {
			thread = tb.getOrAddThread("Threads[0]", 0);
			DBTraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(0,
				new RegisterValue(tb.language.getRegister("cpsr"), BigInteger.ONE.shiftLeft(5)));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		waitForSwing();

		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		ListingActionContext actionContext = createActionContext(start, 4);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(2, ins.getLength());
	}

	@Test
	public void testCurrentDisassembleActionGuestArm() throws Throwable {
		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x1e, 0xff, 0x2f, 0xe1));
		traceManager.activateThread(thread);
		waitForSwing();

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		TracePlatform arm = Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms());
		// If cpsr is UNKNOWN, inject will assume, e.g., Cortex-M, and set THUMB mode.
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createObject(
						TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0].Registers"))
					.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			DBTraceMemorySpace regs = Objects.requireNonNull(
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true));
			Register cpsr = arm.getLanguage().getRegister("cpsr");
			regs.setValue(arm, 0, new RegisterValue(cpsr, BigInteger.ZERO));
		}
		waitForDomainObject(tb.trace);

		Address start = tb.addr(0x00400000);

		ListingActionContext actionContext = createActionContext(start, 4);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(4, ins.getLength());
	}

	@Test
	public void testCurrentDisassembleActionGuestThumb() throws Throwable {
		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x70, 0x47));
		traceManager.activateThread(thread);
		waitForSwing();

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		TracePlatform arm = Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms());
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager()
					.createObject(
						TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0].Registers"))
					.insert(Lifespan.nowOn(0), ConflictResolution.DENY);
			DBTraceMemorySpace regs = Objects.requireNonNull(
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true));
			Register cpsr = arm.getLanguage().getRegister("cpsr");
			regs.setValue(arm, 0, new RegisterValue(cpsr, BigInteger.ONE.shiftLeft(5)));
		}
		waitForDomainObject(tb.trace);

		Address start = tb.addr(0x00400000);

		ListingActionContext actionContext = createActionContext(start, 4);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(2, ins.getLength());
	}

	protected void performFixedDisassembleAction(Address start,
			Predicate<DockingActionIf> actionPred) {
		ListingActionContext actionContext = createActionContext(start, 4);
		DockingActionIf action =
			runSwing(() -> Unique.assertOne(disassemblerPlugin.getPopupActions(tool, actionContext)
					.stream()
					.filter(a -> a.isAddToPopup(actionContext))
					.filter(actionPred)));
		performAction(action, actionContext, true);
		waitForTasks();
	}

	@Test
	public void testFixedDisassembleActionsHostArm() throws Throwable {
		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf(0x1e, 0xff, 0x2f, 0xe1));
		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		performFixedDisassembleAction(start, a -> !a.getName().contains("v8T"));

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(4, ins.getLength());
	}

	@Test
	public void testFixedDisassembleActionsGuestArm() throws Throwable {
		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x1e, 0xff, 0x2f, 0xe1));
		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		performFixedDisassembleAction(start, a -> !a.getName().contains("v8T"));

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(4, ins.getLength());
	}

	@Test
	public void testFixedDisassembleActionsGuestThumb() throws Throwable {
		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x70, 0x47));
		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		performFixedDisassembleAction(start, a -> a.getName().contains("v8T"));

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(2, ins.getLength());
	}

	@Test
	public void testCurrentAssembleActionHostArm() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf(0x00, 0x00, 0x00, 0x00));
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		try (Transaction tx = tb.startTransaction()) {
			tb.addInstruction(0, start, tb.host);
		}
		waitForDomainObject(tb.trace);

		ListingActionContext actionContext = createActionContext(start, 2);
		assertTrue(disassemblerPlugin.actionPatchInstruction.isEnabledForContext(actionContext));
		DebuggerDisassemblerPluginTestHelper helper = new DebuggerDisassemblerPluginTestHelper(
			disassemblerPlugin, listingProvider, tb.trace.getProgramView());
		Instruction result = helper.patchInstructionAt(start, "andeq r0,r0,r0", "bx lr");

		assertArrayEquals(tb.arr(0x1e, 0xff, 0x2f, 0xe1), result.getBytes());
		assertNull(result.getNext());
	}

	@Test
	public void testCurrentAssembleActionHostThumb() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		// Don't cheat here and choose v8T!
		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf(0x00, 0x00));
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		try (Transaction tx = tb.startTransaction()) {
			TraceDisassembleCommand dis = new TraceDisassembleCommand(tb.host, start,
				new AddressSet(start, start.addWrap(1)));
			dis.setInitialContext(DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
				tb.language, new LanguageID("ARM:LE:32:v8T"), start));
			dis.applyTo(tb.trace.getProgramView(), TaskMonitor.DUMMY);
		}
		waitForDomainObject(tb.trace);

		ListingActionContext actionContext = createActionContext(start, 2);
		assertTrue(disassemblerPlugin.actionPatchInstruction.isEnabledForContext(actionContext));
		DebuggerDisassemblerPluginTestHelper helper = new DebuggerDisassemblerPluginTestHelper(
			disassemblerPlugin, listingProvider, tb.trace.getProgramView());
		Instruction result = helper.patchInstructionAt(start, "movs r0,r0", "bx lr");

		assertArrayEquals(tb.arr(0x70, 0x47), result.getBytes());
		assertNull(result.getNext());
	}

	@Test
	public void testCurrentAssembleActionGuestArm() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x00, 0x00, 0x00, 0x00));
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		TraceGuestPlatform guest =
			Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms());
		try (Transaction tx = tb.startTransaction()) {
			tb.addInstruction(0, start, guest);
		}
		waitForDomainObject(tb.trace);

		ListingActionContext actionContext = createActionContext(start, 2);
		assertTrue(disassemblerPlugin.actionPatchInstruction.isEnabledForContext(actionContext));
		DebuggerDisassemblerPluginTestHelper helper = new DebuggerDisassemblerPluginTestHelper(
			disassemblerPlugin, listingProvider, tb.trace.getProgramView());
		Instruction result = helper.patchInstructionAt(start, "andeq r0,r0,r0", "bx lr");

		assertArrayEquals(tb.arr(0x1e, 0xff, 0x2f, 0xe1), result.getBytes());
		assertNull(result.getNext());
	}

	@Test
	public void testCurrentAssembleActionGuestThumb() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x00, 0x00));
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		waitForPass(() -> Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms()));
		TraceGuestPlatform guest =
			Unique.assertOne(tb.trace.getPlatformManager().getGuestPlatforms());
		try (Transaction tx = tb.startTransaction()) {
			TraceDisassembleCommand dis =
				new TraceDisassembleCommand(guest, start, new AddressSet(start, start.addWrap(1)));
			dis.setInitialContext(DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
				guest.getLanguage(), new LanguageID("ARM:LE:32:v8T"), start));
			dis.applyTo(tb.trace.getProgramView(), TaskMonitor.DUMMY);
		}
		waitForDomainObject(tb.trace);

		ListingActionContext actionContext = createActionContext(start, 2);
		assertTrue(disassemblerPlugin.actionPatchInstruction.isEnabledForContext(actionContext));
		DebuggerDisassemblerPluginTestHelper helper = new DebuggerDisassemblerPluginTestHelper(
			disassemblerPlugin, listingProvider, tb.trace.getProgramView());
		Instruction result = helper.patchInstructionAt(start, "movs r0,r0", "bx lr");

		assertArrayEquals(tb.arr(0x70, 0x47), result.getBytes());
		assertNull(result.getNext());
	}

	protected Instruction performFixedAssembleAction(Address start,
			Predicate<FixedPlatformTracePatchInstructionAction> actionPred, String assembly) {
		ListingActionContext actionContext = createActionContext(start, 2);
		FixedPlatformTracePatchInstructionAction action =
			runSwing(() -> Unique.assertOne(disassemblerPlugin.getPopupActions(tool, actionContext)
					.stream()
					.filter(a -> a instanceof FixedPlatformTracePatchInstructionAction)
					.map(a -> (FixedPlatformTracePatchInstructionAction) a)
					.filter(actionPred)));

		AssemblerPluginTestHelper helper =
			new AssemblerPluginTestHelper(action, null, listingProvider, tb.trace.getProgramView());
		return helper.patchInstructionAt(start, "", assembly);
	}

	@Test
	public void testFixedAssembleActionsHostArm() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		createLegacyTrace("ARM:LE:32:v8", 0x00400000, () -> tb.buf());
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, null, 0));

		Instruction result =
			performFixedAssembleAction(start, a -> !a.getName().contains("v8T"), "bx lr");

		assertArrayEquals(tb.arr(0x1e, 0xff, 0x2f, 0xe1), result.getBytes());
		assertNull(result.getNext());
	}

	@Test
	public void testFixedAssembleActionsGuestArm() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		TraceObjectThread thread = createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf());
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		Instruction result =
			performFixedAssembleAction(start, a -> !a.getName().contains("v8T"), "bx lr");

		assertArrayEquals(tb.arr(0x1e, 0xff, 0x2f, 0xe1), result.getBytes());
		assertNull(result.getNext());
	}

	@Test
	public void testFixedAssembleActionsGuestThumb() throws Throwable {
		// Assemble actions will think read-only otherwise
		DebuggerControlService controlService = addPlugin(tool, DebuggerControlServicePlugin.class);

		TraceObjectThread thread = createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf());
		Address start = tb.addr(0x00400000);
		controlService.setCurrentMode(tb.trace, ControlMode.RW_TRACE);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		Instruction result =
			performFixedAssembleAction(start, a -> a.getName().contains("v8T"), "bx lr");

		assertArrayEquals(tb.arr(0x70, 0x47), result.getBytes());
		assertNull(result.getNext());
	}
}
