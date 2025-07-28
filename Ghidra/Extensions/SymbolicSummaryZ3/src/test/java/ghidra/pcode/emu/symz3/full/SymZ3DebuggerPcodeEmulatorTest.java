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
package ghidra.pcode.emu.symz3.full;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorState;
import ghidra.pcode.emu.symz3.trace.SymZ3TracePcodeExecutorStatePiece;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder.ToySchemaBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapSpace;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class SymZ3DebuggerPcodeEmulatorTest extends AbstractGhidraHeadedDebuggerTest {
	private DebuggerStaticMappingService mappingService;
	private DebuggerEmulationService emuService;

	@Before
	public void setUpSymTest() throws Throwable {
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
	}

	@Test
	public void testFactoryDiscovered() {
		assertEquals(1, emuService.getEmulatorFactories()
				.stream()
				.filter(f -> f instanceof SymZ3DebuggerPcodeEmulatorFactory)
				.count());
	}

	protected SchemaContext buildContext() {
		return new ToySchemaBuilder()
				.noRegisterGroups()
				.useRegistersPerFrame()
				.build();
	}

	@Test
	public void testFactoryCreate() throws Exception {
		emuService.setEmulatorFactory(new SymZ3DebuggerPcodeEmulatorFactory());

		createAndOpenTrace();

		TraceThread thread;
		try (Transaction tid = tb.startTransaction()) {
			tb.createRootObject(buildContext(), "Target");
			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
		}

		traceManager.activateTrace(tb.trace);

		EmulationResult result =
			emuService.run(tb.host, TraceSchedule.snap(0), monitor, new Scheduler() {
				int calls = 0;

				@Override
				public TickStep nextSlice(Trace trace) {
					// Expect decode of uninitialized memory immediately
					assertEquals(0, calls++);
					return new TickStep(thread.getKey(), 1);
				}
			});

		DebuggerPcodeMachine<?> emu = emuService.getCachedEmulator(tb.trace, result.schedule());
		assertTrue(emu instanceof SymZ3DebuggerPcodeEmulator);

		SymZ3TracePcodeExecutorState state = (SymZ3TracePcodeExecutorState) emu.getSharedState();
		Msg.debug(this, "here is your state: " + state);
	}

	@Test
	public void testReadsProgramUsrProperties() throws Exception {
		emuService.setEmulatorFactory(new SymZ3DebuggerPcodeEmulatorFactory());

		createAndOpenTrace("x86:LE:64:default");
		createProgramFromTrace();

		intoProject(program);
		intoProject(tb.trace);

		programManager.openProgram(program);

		TraceThread thread;
		try (Transaction tid = tb.startTransaction()) {
			tb.createRootObject(buildContext(), "Target");
			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x55550000)),
				new ProgramLocation(program, tb.addr(0x00400000)), 0x1000, false);
			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
			tb.exec(0, thread, 0, """
					RIP = 0x55550000;
					""");
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals(new ProgramLocation(program, tb.addr(0x00400000)),
			mappingService.getOpenMappedLocation(
				new DefaultTraceLocation(tb.trace, null, Lifespan.at(0), tb.addr(0x55550000)))));

		try (Transaction tid = program.openTransaction("Assemble")) {
			program.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			StringPropertyMap progSymMap = program.getUsrPropertyManager()
					.createStringPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME);

			progSymMap.add(tb.addr(0x00400800), "test_0");
			Assembler asm = Assemblers.getAssembler(program);

			// TODO: I should be able to make this use a RIP-relative address
			asm.assemble(tb.addr(0x00400000),
				"MOV RAX, [0x55550800]"); // was [0x00400800], but fixed address is a problem.
		}

		TraceSchedule time = TraceSchedule.parse("0:t%d-1".formatted(thread.getKey()));
		long scratch = emuService.emulate(tb.trace, time, TaskMonitor.DUMMY);

		TracePropertyMap<String> traceSymMap = tb.trace.getAddressPropertyManager()
				.getPropertyMap(SymZ3TracePcodeExecutorStatePiece.NAME, String.class);
		TracePropertyMapSpace<String> symRegSpace =
			traceSymMap.getPropertyMapRegisterSpace(thread, 0, false);

		Msg.info(this, symRegSpace.getEntries(Lifespan.at(scratch), tb.reg("RAX")));

		//SymZ3DebuggerPcodeEmulator emu =
		//	(SymZ3DebuggerPcodeEmulator) emuService.getCachedEmulator(tb.trace, time);
		//emu.printSymbolicSummary();
	}
}
