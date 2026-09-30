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
package ghidra.app.plugin.core.debug.gui.decompiler;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.*;

import javax.swing.Icon;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import generic.Unique;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointMarkerPlugin;
import ghidra.app.plugin.core.debug.gui.breakpoint.MockDecompileResults;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingUtils;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.debug.api.breakpoint.LogicalBreakpoint;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.database.ToyDBTraceBuilder.ToySchemaBuilder;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.thread.TraceThread;

public class DebuggerDecompilerTrackLocationPluginTest
		extends AbstractGhidraHeadedDebuggerIntegrationTest {

	/**
	 * Lines of the mock decompilation:
	 *
	 * <pre>
	 * 0: test()          (no address)
	 * 1: x = 1;          0x00600000 (dynamic 0x00400000)
	 * 2: y = 2;          0x00600004 (dynamic 0x00400004)
	 * </pre>
	 */
	protected static final int LINE_X = 1;
	protected static final int LINE_Y = 2;

	protected DebuggerDecompilerTrackLocationPlugin trackPlugin;
	protected DebuggerDecompilerMarginServicePlugin marginPlugin;
	protected DecompilerProvider decompilerProvider;

	protected Function function;
	protected Address entry;
	protected TraceThread thread;

	@Before
	public void setUpDecompilerTrackLocationPluginTest() throws Exception {
		addPlugin(tool, DecompilePlugin.class);
		decompilerProvider = waitForComponentProvider(DecompilerProvider.class);
		runSwing(() -> tool.showComponentProvider(decompilerProvider, true));
		trackPlugin = addPlugin(tool, DebuggerDecompilerTrackLocationPlugin.class);
		marginPlugin = (DebuggerDecompilerMarginServicePlugin) tool
				.getService(DebuggerDecompilerMarginService.class);
	}

	protected SchemaContext buildContext() {
		return new ToySchemaBuilder()
				.noRegisterGroups()
				.useRegistersPerFrame()
				.build();
	}

	/**
	 * Create a trace and a program mapped from it, with one thread and a function in the program
	 */
	protected void createMappedTraceAndProgram() throws Throwable {
		createAndOpenTrace();
		createAndOpenProgramFromTrace();
		intoProject(tb.trace);
		intoProject(program);

		AddressSpace ss = program.getAddressFactory().getDefaultAddressSpace();
		entry = ss.getAddress(0x00600000);
		try (Transaction tx = program.openTransaction("Add block and function")) {
			program.getMemory()
					.createInitializedBlock(".text", entry, 0x10000, (byte) 0, monitor, false);
			function = program.getFunctionManager()
					.createFunction("test", entry, new AddressSet(entry, entry.add(0xf)),
						SourceType.USER_DEFINED);
		}
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject(buildContext(), "Target");
			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.addRegion("Memory[exe:.text]", Lifespan.nowOn(0),
				tb.range(0x00400000, 0x0040ffff),
				TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE);
			TraceLocation from =
				new DefaultTraceLocation(tb.trace, null, Lifespan.nowOn(0), tb.addr(0x00400000));
			ProgramLocation to = new ProgramLocation(program, entry);
			DebuggerStaticMappingUtils.addMapping(from, to, 0x8000, false);

			thread = tb.getOrAddThread("Threads[1]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
		}
		waitForProgram(program);
		waitForDomainObject(tb.trace);
	}

	protected void setMockDecompileData() {
		DecompileResults results = new MockDecompileResults(function) {
			{
				root(function(
					token("test()"), brk(),
					token("x = 1;", entry), brk(),
					token("y = 2;", entry.add(4))));
			}

			ClangBuilder<ClangBreak> brk() {
				return ClangBreak::new;
			}
		};
		Program p = function.getProgram();
		DecompileData data = new DecompileData(p, function, new ProgramLocation(p, entry),
			results, "", null, null);
		runSwing(() -> decompilerProvider.getController().setDecompileData(data));
		waitForPass(() -> assertEquals(3, getLines().size()));
	}

	protected void setRegister(Register register, long snap, long value) {
		try (Transaction tx = tb.startTransaction()) {
			TraceMemorySpace regs =
				tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
			regs.setValue(snap, new RegisterValue(register, BigInteger.valueOf(value)));
		}
		waitForDomainObject(tb.trace);
	}

	protected void setPc(long value) {
		setRegister(tb.language.getProgramCounter(), 0, value);
	}

	protected List<ClangLine> getLines() {
		return runSwing(() -> decompilerProvider.getDecompilerPanel().getLines());
	}

	protected List<Icon> getIcons(int line) {
		return runSwing(() -> marginPlugin.marginProvider.getIcons(getLines().get(line)));
	}

	protected Set<String> getHighlightedText() {
		return runSwing(() -> {
			DecompilerPanel panel = decompilerProvider.getDecompilerPanel();
			TokenHighlights highlights =
				panel.getHighlightController().getHighlighterHighlights(trackPlugin.highlighter);
			Set<String> result = new HashSet<>();
			if (highlights == null) {
				return result;
			}
			for (HighlightToken hl : highlights) {
				result.add(hl.getToken().getText());
			}
			return result;
		});
	}

	/**
	 * Assert the tracked location is marked on the given line, and only that line
	 *
	 * @param line the line, or -1 to assert no line is marked
	 */
	protected void assertMarkedLine(int line) {
		waitForPass(() -> {
			for (int i = 0; i < getLines().size(); i++) {
				assertEquals("Icon on line " + i, i == line,
					getIcons(i).contains(DebuggerDecompilerTrackLocationPlugin.ICON_TRACKED));
			}
			Set<String> expected = switch (line) {
				case LINE_X -> Set.of("x = 1;");
				case LINE_Y -> Set.of("y = 2;");
				default -> Set.of();
			};
			assertEquals(expected, getHighlightedText());
		});
	}

	@Test
	public void testNoTraceNoMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();

		assertNull(trackPlugin.getStaticLocation());
		assertMarkedLine(-1);
	}

	@Test
	public void testNoDecompilationNoErrors() throws Throwable {
		createMappedTraceAndProgram();
		traceManager.activateThread(thread);
		setPc(0x00400004);

		waitForPass(() -> assertEquals(new ProgramLocation(program, entry.add(4)),
			trackPlugin.getStaticLocation()));
	}

	@Test
	public void testActivateThenUpdatePcMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();

		traceManager.activateThread(thread);
		waitForSwing();
		assertMarkedLine(-1);

		setPc(0x00400004);
		assertMarkedLine(LINE_Y);
	}

	@Test
	public void testUpdatePcThenActivateMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();

		setPc(0x00400004);
		assertMarkedLine(-1);

		traceManager.activateThread(thread);
		assertMarkedLine(LINE_Y);
	}

	@Test
	public void testDecompileAfterTrackingMarks() throws Throwable {
		createMappedTraceAndProgram();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		waitForPass(() -> assertNotNull(trackPlugin.getStaticLocation()));

		setMockDecompileData();
		assertMarkedLine(LINE_Y);
	}

	@Test
	public void testPcChangeMovesMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		setPc(0x00400000);
		assertMarkedLine(LINE_X);
	}

	@Test
	public void testStackPcMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		try (Transaction tx = tb.startTransaction()) {
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.getFrame(0, 0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00400004));
		}
		waitForDomainObject(tb.trace);
		traceManager.activateThread(thread);
		assertMarkedLine(LINE_Y);

		try (Transaction tx = tb.startTransaction()) {
			TraceStack stack = tb.trace.getStackManager().getStack(thread, 0, true);
			stack.getFrame(0, 0, true).setProgramCounter(Lifespan.ALL, tb.addr(0x00400000));
		}
		waitForDomainObject(tb.trace);
		assertMarkedLine(LINE_X);
	}

	@Test
	public void testSnapChangeMovesMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		Register pc = tb.language.getProgramCounter();
		setRegister(pc, 0, 0x00400004);
		setRegister(pc, 1, 0x00400000);
		traceManager.activateThread(thread);
		assertMarkedLine(LINE_Y);

		traceManager.activateSnap(1);
		assertMarkedLine(LINE_X);
	}

	@Test
	public void testPcOutsideFunctionNoMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		setPc(0x00400100);
		waitForPass(() -> assertEquals(new ProgramLocation(program, entry.add(0x100)),
			trackPlugin.getStaticLocation()));
		assertMarkedLine(-1);
	}

	@Test
	public void testPcUnmappedNoMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		setPc(0x00500000);
		waitForPass(() -> assertNull(trackPlugin.getStaticLocation()));
		assertMarkedLine(-1);
	}

	@Test
	public void testCloseTraceClearsMarks() throws Throwable {
		createMappedTraceAndProgram();
		setMockDecompileData();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		traceManager.closeTraceNoConfirm(tb.trace);
		waitForSwing();
		assertMarkedLine(-1);
	}

	@Test
	public void testListingTrackingSpecChangeUpdatesImmediately() throws Throwable {
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		assertEquals(PCLocationTrackingSpec.INSTANCE, trackPlugin.getTrackingSpec());

		createMappedTraceAndProgram();
		setMockDecompileData();
		setRegister(tb.trace.getBaseCompilerSpec().getStackPointer(), 0, 0x00400000);
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		runSwing(() -> listingPlugin.setTrackingSpec(SPLocationTrackingSpec.INSTANCE));
		waitForPass(() -> assertEquals(SPLocationTrackingSpec.INSTANCE,
			trackPlugin.getTrackingSpec()));
		assertMarkedLine(LINE_X);

		runSwing(() -> listingPlugin.setTrackingSpec(NoneLocationTrackingSpec.INSTANCE));
		waitForPass(() -> assertEquals(NoneLocationTrackingSpec.INSTANCE,
			trackPlugin.getTrackingSpec()));
		assertMarkedLine(-1);

		runSwing(() -> listingPlugin.setTrackingSpec(PCLocationTrackingSpec.INSTANCE));
		assertMarkedLine(LINE_Y);
	}

	@Test
	public void testListingWatchTrackingSpec() throws Throwable {
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);

		createMappedTraceAndProgram();
		setMockDecompileData();
		setRegister(tb.language.getRegister("r0"), 0, 0x00400000);
		traceManager.activateThread(thread);
		setPc(0x00400000);
		assertMarkedLine(LINE_X);

		runSwing(() -> listingPlugin.setTrackingSpec(new WatchLocationTrackingSpec("*:4 (r0+4)")));
		assertMarkedLine(LINE_Y);
	}

	@Test
	public void testAdoptsListingTrackingSpecWhenAddedLater() throws Throwable {
		runSwing(() -> tool.removePlugins(List.of(trackPlugin)));
		DebuggerListingPlugin listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		runSwing(() -> listingPlugin.setTrackingSpec(SPLocationTrackingSpec.INSTANCE));

		trackPlugin = addPlugin(tool, DebuggerDecompilerTrackLocationPlugin.class);
		assertEquals(SPLocationTrackingSpec.INSTANCE, trackPlugin.getTrackingSpec());
	}

	@Test
	public void testSharesMarginWithBreakpoints() throws Throwable {
		addPlugin(tool, CodeBrowserPlugin.class);
		addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		DebuggerLogicalBreakpointService breakpointService =
			tool.getService(DebuggerLogicalBreakpointService.class);

		createMappedTraceAndProgram();
		setMockDecompileData();
		traceManager.activateThread(thread);
		setPc(0x00400004);
		assertMarkedLine(LINE_Y);

		try (Transaction tx = program.openTransaction("Add breakpoint")) {
			program.getBookmarkManager()
					.setBookmark(entry.add(4), LogicalBreakpoint.ENABLED_BOOKMARK_TYPE, "x;1", "");
		}
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, entry.add(4))));
		Icon breakpointIcon = lb.computeStateForProgram(program).icon;
		assertNotNull(breakpointIcon);
		// Lowest priority first, so the breakpoint is painted on top, as in the listings
		waitForPass(() -> assertEquals(
			List.of(DebuggerDecompilerTrackLocationPlugin.ICON_TRACKED, breakpointIcon),
			getIcons(LINE_Y)));
		assertEquals(List.of(), getIcons(LINE_X));
	}
}
