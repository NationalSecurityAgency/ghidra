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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Set;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.junit.*;

import db.Transaction;
import docking.action.DockingActionIf;
import generic.Unique;
import ghidra.app.context.ListingActionContext;
import ghidra.app.plugin.core.assembler.AssemblerPluginTestHelper;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.service.control.DebuggerControlServicePlugin;
import ghidra.app.plugin.core.debug.service.platform.DebuggerPlatformServicePlugin;
import ghidra.app.plugin.core.debug.service.workflow.DebuggerWorkflowServiceProxyPlugin;
import ghidra.app.plugin.core.debug.workflow.DisassembleAtPcDebuggerBot;
import ghidra.app.services.*;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.trace.database.listing.DBTraceInstruction;
import ghidra.trace.database.listing.DBTraceInstructionsMemoryView;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.database.program.DBTraceVariableSnapProgramView;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.task.TaskMonitor;

public class DebuggerDisassemblyTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerDisassemblerPlugin disassemblerPlugin;
	protected DebuggerPlatformService platformService;
	protected DebuggerListingProvider listingProvider;
	protected SchemaContext ctx;

	@Before
	public void setUpDisassemblyTest() throws Exception {
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Targets' schema='TargetContainer' />" + //
			"    </schema>" + //
			"    <schema name='TargetContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Target' />" + //
			"    </schema>" + //
			"    <schema name='Target' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Process' />" + //
			"        <interface name='Aggregate' />" + //
			"        <attribute name='Environment' schema='Environment' />" + //
			"        <attribute name='Memory' schema='Memory' />" + //
			"        <attribute name='Threads' schema='ThreadContainer' />" + //
			"    </schema>" + //
			"    <schema name='Environment' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <interface name='Environment' />" + //
			"    </schema>" + //
			"    <schema name='Memory' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <element schema='MemoryRegion' />" + //
			"    </schema>" + //
			"    <schema name='MemoryRegion' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='MemoryRegion' />" + //
			"    </schema>" + //
			"    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <element schema='Thread' />" + //
			"    </schema>" + //
			"    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Thread' />" + //
			"        <interface name='Aggregate' />" + //
			"        <attribute name='Stack' schema='Stack' />" + //
			"    </schema>" + //
			"    <schema name='Stack' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <interface name='Stack' />" + //
			"        <element schema='Frame' />" + //
			"    </schema>" + //
			"    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='StackFrame' />" + //
			"    </schema>" + //
			"</context>");

		addPlugin(tool, DebuggerListingPlugin.class);
		platformService = addPlugin(tool, DebuggerPlatformServicePlugin.class);
		disassemblerPlugin = addPlugin(tool, DebuggerDisassemblerPlugin.class);
		listingProvider = waitForComponentProvider(DebuggerListingProvider.class);
	}

	protected void assertX86Nop(Instruction instruction) {
		assertNotNull(instruction);
		assertEquals("NOP", instruction.getMnemonicString());
	}

	protected void enableAutoDisassembly() throws Throwable {
		DebuggerWorkflowService workflowService =
			addPlugin(tool, DebuggerWorkflowServiceProxyPlugin.class);
		Set<DebuggerBot> disBot = workflowService.getAllBots()
				.stream()
				.filter(b -> b instanceof DisassembleAtPcDebuggerBot)
				.collect(Collectors.toSet());
		assertEquals(1, disBot.size());
		workflowService.enableBots(disBot);
	}

	protected TraceObjectThread createPolyglotTrace(String arch, long offset,
			Supplier<ByteBuffer> byteSupplier) throws IOException {
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

			DBTraceObject objFrame =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0]"));
			objFrame.insert(zeroOn, ConflictResolution.DENY);
			TraceObjectStackFrame frame = objFrame.queryInterface(TraceObjectStackFrame.class);
			frame.setProgramCounter(zeroOn, tb.addr(offset));

			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			ByteBuffer bytes = byteSupplier.get();
			assertEquals(bytes.remaining(), memory.putBytes(0, tb.addr(offset), bytes));
		}
		TraceObjectThread thread =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Targets[0].Threads[0]"))
					.queryInterface(TraceObjectThread.class);
		traceManager.activateThread(thread);
		return thread;
	}

	protected void createLegacyTrace(String langID, long offset,
			Supplier<ByteBuffer> byteSupplier) throws Throwable {
		createAndOpenTrace(langID);

		try (Transaction tx = tb.startTransaction()) {
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.createRegion("Memory[bin:.text]", 0, tb.range(offset, offset + 0xffff),
				Set.of(TraceMemoryFlag.EXECUTE));
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
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400000)));
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400001)));
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400002)));
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

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(3)), null);
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

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(3)), null);
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

		// Set up registers so injects will select ARM
		// TODO

		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(3)), null);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(4, ins.getLength());
	}

	@Test
	@Ignore("TODO")
	public void testCurrentDisassembleActionGuestThumb() throws Throwable {
		TraceObjectThread thread =
			createPolyglotTrace("armv8le", 0x00400000, () -> tb.buf(0x70, 0x47));

		// Set up registers to injects will select THUMB
		// TODO

		Address start = tb.addr(0x00400000);

		// Ensure the mapper is added to the trace
		assertNotNull(platformService.getMapper(tb.trace, thread.getObject(), 0));

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(3)), null);
		performAction(disassemblerPlugin.actionDisassemble, actionContext, true);
		waitForTasks();

		DBTraceInstruction ins = tb.trace.getCodeManager().instructions().getAt(0, start);
		assertNotNull(ins);
		assertEquals("bx lr", ins.toString());
		assertEquals(2, ins.getLength());
	}

	protected void performFixedDisassembleAction(Address start,
			Predicate<DockingActionIf> actionPred) {
		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(3)), null);
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

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(1)), null);

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
			dis.applyToTyped(tb.trace.getProgramView(), TaskMonitor.DUMMY);
		}
		waitForDomainObject(tb.trace);

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(1)), null);

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

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(1)), null);

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
			TraceDisassembleCommand dis = new TraceDisassembleCommand(guest, start,
				new AddressSet(start, start.addWrap(1)));
			dis.setInitialContext(DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
				guest.getLanguage(), new LanguageID("ARM:LE:32:v8T"), start));
			dis.applyToTyped(tb.trace.getProgramView(), TaskMonitor.DUMMY);
		}
		waitForDomainObject(tb.trace);

		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(1)), null);

		assertTrue(disassemblerPlugin.actionPatchInstruction.isEnabledForContext(actionContext));
		DebuggerDisassemblerPluginTestHelper helper = new DebuggerDisassemblerPluginTestHelper(
			disassemblerPlugin, listingProvider, tb.trace.getProgramView());
		Instruction result = helper.patchInstructionAt(start, "movs r0,r0", "bx lr");

		assertArrayEquals(tb.arr(0x70, 0x47), result.getBytes());
		assertNull(result.getNext());
	}

	protected Instruction performFixedAssembleAction(Address start,
			Predicate<FixedPlatformTracePatchInstructionAction> actionPred, String assembly) {
		DBTraceVariableSnapProgramView view = tb.trace.getProgramView();
		ListingActionContext actionContext = new ListingActionContext(listingProvider,
			listingProvider, view, new ProgramLocation(view, start),
			new ProgramSelection(start, start.addWrap(1)), null);
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
