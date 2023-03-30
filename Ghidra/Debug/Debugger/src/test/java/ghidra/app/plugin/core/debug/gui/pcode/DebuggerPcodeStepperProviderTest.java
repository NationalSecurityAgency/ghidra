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
package ghidra.app.plugin.core.debug.gui.pcode;

import static org.junit.Assert.*;

import java.lang.invoke.MethodHandles;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperProvider.PcodeRowHtmlFormatter;
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;

public class DebuggerPcodeStepperProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerTraceManagerService traceManager;
	protected DebuggerPcodeStepperPlugin pcodePlugin;
	protected DebuggerListingPlugin listingPlugin;

	protected DebuggerPcodeStepperProvider pcodeProvider;
	protected DebuggerEmulationService emuService;

	private Address start;
	private TraceThread thread;
	private Instruction imm123;

	@Before
	public void setUpPcodeStepperProviderTest() throws Exception {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		pcodePlugin = addPlugin(tool, DebuggerPcodeStepperPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class); // For colors
		emuService = tool.getService(DebuggerEmulationService.class);

		pcodeProvider = waitForComponentProvider(DebuggerPcodeStepperProvider.class);

		createTrace();
	}

	protected void populateTrace() throws Exception {
		start = tb.addr(0x00400000);
		InstructionIterator iit;
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("echo:.text", Lifespan.nowOn(0), tb.range(0x00400000, 0x0040ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			thread = tb.getOrAddThread("1", 0);

			PcodeExecutor<byte[]> init = TraceSleighUtils.buildByteExecutor(tb.trace, 0, thread, 0);
			init.executeSleigh("pc = 0x00400000;");

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			iit = asm.assemble(start, "imm r0, #0x123");

		}
		imm123 = iit.next();
	}

	protected void assertEmpty() {
		assertTrue(pcodeProvider.pcodeTableModel.getModelData().isEmpty());
		assertTrue(pcodeProvider.uniqueTableModel.getModelData().isEmpty());
	}

	protected void assertDecodeStep() {
		PcodeRow row = Unique.assertOne(pcodeProvider.pcodeTableModel.getModelData());
		assertEquals(EnumPcodeRow.DECODE, row);
		assertTrue(pcodeProvider.uniqueTableModel.getModelData().isEmpty());
	}

	protected void assertPopulated() {
		assertFalse(pcodeProvider.pcodeTableModel.getModelData().isEmpty());
		// NB. I don't know what uniques, if any, are involved
	}

	@Test
	public void testEmpty() throws Exception {
		assertEmpty();
	}

	@Test
	public void testCloseCurrentTraceEmpty() throws Exception {
		populateTrace();

		TraceSchedule schedule1 = TraceSchedule.parse("0:.t0-1");
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		waitForPass(() -> assertDecodeStep());

		traceManager.activateTime(schedule1);
		waitForPass(() -> assertEquals(schedule1, pcodeProvider.current.getTime()));
		waitForPass(() -> assertPopulated());

		traceManager.closeTrace(tb.trace);
		waitForPass(() -> assertEmpty());
	}

	@Test
	public void testCustomUseropDisplay() throws Exception {
		populateTrace();

		emuService.setEmulatorFactory(new BytesDebuggerPcodeEmulatorFactory() {
			@Override
			public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
				BytesDebuggerPcodeEmulator emu = new BytesDebuggerPcodeEmulator(access) {
					@Override
					protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
						return new AnnotatedPcodeUseropLibrary<byte[]>() {
							@Override
							protected MethodHandles.Lookup getMethodLookup() {
								return MethodHandles.lookup();
							}

							@PcodeUserop
							public void stepper_test_userop() {
								// stub
							}
						};
					}
				};
				emu.inject(imm123.getAddress(), "stepper_test_userop();");
				return emu;
			}
		});

		// Just one p-code step to load injection (decode step)
		TraceSchedule schedule1 = TraceSchedule.parse("0:.t0-1");
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		traceManager.activateTime(schedule1);
		waitForPass(() -> assertEquals(schedule1, pcodeProvider.current.getTime()));

		waitForPass(() -> assertTrue(pcodeProvider.pcodeTableModel.getModelData()
				.stream()
				.anyMatch(r -> r.getCode().contains("stepper_test_userop"))));
	}

	protected List<PcodeRow> format(String sleigh) {
		SleighLanguage language = (SleighLanguage) getToyBE64Language();
		PcodeProgram prog = SleighProgramCompiler.compileProgram(language, "test", sleigh,
			PcodeUseropLibrary.nil());
		PcodeExecutor<byte[]> executor =
			new PcodeExecutor<>(language, BytesPcodeArithmetic.BIG_ENDIAN, null, Reason.INSPECT);
		PcodeFrame frame = executor.begin(prog);
		PcodeRowHtmlFormatter formatter = pcodeProvider.new PcodeRowHtmlFormatter(language, frame);
		return formatter.getRows();
	}

	@Test
	public void testPcodeFormatterSimple() {
		List<PcodeRow> rows = format("r0 = 1;");
		assertEquals(2, rows.size());
		assertEquals("<html></html>", rows.get(0).getLabel());
		assertEquals(FallthroughPcodeRow.class, rows.get(1).getClass());
	}

	@Test
	public void testPcodeFormatterStartsLabel() {
		List<PcodeRow> rows = format("""
				<L0> r0 = 1;
				goto <L0>;
				""");
		assertEquals(3, rows.size());
		assertEquals("<html><font color=\"Blue\">&lt;0&gt;</font></html>", rows.get(0).getLabel());
		assertEquals("<html></html>", rows.get(1).getLabel());
		assertEquals(FallthroughPcodeRow.class, rows.get(2).getClass());
	}

	@Test
	public void testPcodeFormatterMiddleLabel() {
		List<PcodeRow> rows = format("""
				if 1:1 goto <SKIP>;
				r0 = 1;
				<SKIP> r1 = 2;
				""");
		assertEquals(4, rows.size());
		assertEquals("<html></html>", rows.get(0).getLabel());
		assertEquals("<html></html>", rows.get(1).getLabel());
		assertEquals("<html><font color=\"Blue\">&lt;0&gt;</font></html>", rows.get(2).getLabel());
		assertEquals(FallthroughPcodeRow.class, rows.get(3).getClass());
	}

	@Test
	public void testPcodeFormatterFallthroughLabel() {
		List<PcodeRow> rows = format("""
				if 1:1 goto <SKIP>;
				r0 = 1;
				<SKIP>
				""");
		assertEquals(3, rows.size());
		assertEquals("<html></html>", rows.get(0).getLabel());
		assertEquals("<html></html>", rows.get(1).getLabel());
		assertEquals("<html><font color=\"Blue\">&lt;0&gt;</font></html>", rows.get(2).getLabel());
		assertEquals(FallthroughPcodeRow.class, rows.get(2).getClass());
	}

	@Test
	public void testPcodeFormatterManyLabel() {
		List<PcodeRow> rows = format("""
				<L0> goto <L1>;
				<L1> goto <L2>;
				<L2> goto <L3>;
				goto <L0>;
				<L3>
				""");
		assertEquals(5, rows.size());
		// NB. templates number labels in order of appearance in BRANCHes
		assertEquals("<html><font color=\"Blue\">&lt;3&gt;</font></html>", rows.get(0).getLabel());
		assertEquals("<html><font color=\"Blue\">&lt;0&gt;</font></html>", rows.get(1).getLabel());
		assertEquals("<html><font color=\"Blue\">&lt;1&gt;</font></html>", rows.get(2).getLabel());
		assertEquals("<html></html>", rows.get(3).getLabel());
		assertEquals("<html><font color=\"Blue\">&lt;2&gt;</font></html>", rows.get(4).getLabel());
		assertEquals(FallthroughPcodeRow.class, rows.get(4).getClass());
	}
}
