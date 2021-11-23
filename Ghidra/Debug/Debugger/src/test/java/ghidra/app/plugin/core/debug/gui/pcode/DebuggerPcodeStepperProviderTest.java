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

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerTracePcodeEmulator;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.util.database.UndoableTransaction;

public class DebuggerPcodeStepperProviderTest extends AbstractGhidraHeadedDebuggerGUITest {

	protected DebuggerTraceManagerService traceManager;
	protected DebuggerPcodeStepperPlugin pcodePlugin;
	protected DebuggerListingPlugin listingPlugin;

	protected DebuggerPcodeStepperProvider pcodeProvider;
	protected DebuggerEmulationService emuService;

	@Before
	public void setUpPcodeStepperProviderTest() throws Exception {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		pcodePlugin = addPlugin(tool, DebuggerPcodeStepperPlugin.class);
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class); // For colors
		emuService = tool.getService(DebuggerEmulationService.class);

		pcodeProvider = waitForComponentProvider(DebuggerPcodeStepperProvider.class);

		createTrace();
	}

	@Test
	public void testCustomUseropDisplay() throws Exception {
		Address start = tb.addr(0x00400000);
		TraceThread thread;
		InstructionIterator iit;
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getMemoryManager()
					.addRegion("echo:.text", Range.atLeast(0L), tb.range(0x00400000, 0x0040ffff),
						TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);

			thread = tb.getOrAddThread("1", 0);

			PcodeExecutor<byte[]> init = TraceSleighUtils.buildByteExecutor(tb.trace, 0, thread, 0);
			init.executeLine("pc = 0x00400000");

			Assembler asm = Assemblers.getAssembler(tb.trace.getFixedProgramView(0));
			iit = asm.assemble(start,
				"imm r0, #1234",
				"imm r1, #2045"); // 11 bits unsigned

		}
		Instruction imm1234 = iit.next();
		Instruction imm2045 = iit.next();

		TraceSchedule schedule1 = TraceSchedule.parse("0:.t0-1");
		traceManager.openTrace(tb.trace);
		traceManager.activateThread(thread);
		traceManager.activateTime(schedule1);

		DebuggerTracePcodeEmulator emu =
			waitForValue(() -> emuService.getCachedEmulator(tb.trace, schedule1));
		assertNotNull(emu);

		// P-code step to decode already done. One for each op. One to retire.
		TraceSchedule schedule2 =
			schedule1.steppedPcodeForward(thread, imm1234.getPcode().length + 1);
		PcodeThread<byte[]> et = emu.getThread(thread.getPath(), false);
		traceManager.activateTime(schedule2);
		waitForPass(() -> assertNull(et.getFrame()));

		/**
		 * NB. at the moment, there is no API to customize the service's emulator. In the meantime,
		 * the vanilla PcodeThread does inject a custom library for breakpoints, so we'll use that
		 * as our "custom userop" test case. It might also be nice if the emulator service placed
		 * breakpoints, no?
		 */
		emu.addBreakpoint(imm2045.getAddress(), "1:1");

		// Just one to decode is necessary
		TraceSchedule schedule3 = schedule2.steppedPcodeForward(thread, 1);
		traceManager.activateTime(schedule3);
		waitForPass(() -> assertEquals(schedule3, pcodeProvider.current.getTime()));

		assertTrue(pcodeProvider.pcodeTableModel.getModelData()
				.stream()
				.anyMatch(r -> r.getCode().contains("emu_swi")));
	}
}
