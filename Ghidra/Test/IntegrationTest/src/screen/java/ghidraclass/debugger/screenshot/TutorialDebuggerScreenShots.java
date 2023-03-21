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
package ghidraclass.debugger.screenshot;

import static org.junit.Assert.assertTrue;

import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.action.DockingActionIf;
import docking.widgets.fieldpanel.FieldPanel;
import generic.Unique;
import generic.jar.ResourceFile;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.analysis.AutoAnalysisPlugin;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerBreakpointsProvider;
import ghidra.app.plugin.core.debug.gui.console.DebuggerConsoleProvider;
import ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyActionsPlugin;
import ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyIntoProgramDialog;
import ghidra.app.plugin.core.debug.gui.diff.DebuggerTraceViewDiffPlugin;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerMemoryBytesProvider;
import ghidra.app.plugin.core.debug.gui.memory.DebuggerRegionsProvider;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerModulesProvider;
import ghidra.app.plugin.core.debug.gui.modules.DebuggerStaticMappingProvider;
import ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperPlugin;
import ghidra.app.plugin.core.debug.gui.pcode.DebuggerPcodeStepperProvider;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegistersProvider;
import ghidra.app.plugin.core.debug.gui.stack.DebuggerStackProvider;
import ghidra.app.plugin.core.debug.gui.stack.vars.VariableValueHoverPlugin;
import ghidra.app.plugin.core.debug.gui.target.DebuggerTargetsPlugin;
import ghidra.app.plugin.core.debug.gui.thread.DebuggerThreadsProvider;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimeProvider;
import ghidra.app.plugin.core.debug.gui.time.DebuggerTimeSelectionDialog;
import ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchesProvider;
import ghidra.app.plugin.core.debug.gui.watch.WatchRow;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin.EmulateProgramAction;
import ghidra.app.plugin.core.debug.service.model.DebuggerConnectDialog;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer;
import ghidra.app.plugin.core.debug.service.model.launch.DebuggerProgramLaunchOffer.*;
import ghidra.app.plugin.core.debug.stack.StackUnwinderTest;
import ghidra.app.plugin.core.debug.stack.StackUnwinderTest.HoverLocation;
import ghidra.app.plugin.core.debug.stack.UnwindStackCommand;
import ghidra.app.plugin.core.debug.workflow.*;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.app.script.GhidraState;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.async.AsyncTestUtils;
import ghidra.dbg.DebuggerModelFactory;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.testutil.DummyProc;
import ghidra.dbg.util.ConfigurableFactory.Property;
import ghidra.debug.flatapi.FlatDebuggerAPI;
import ghidra.framework.Application;
import ghidra.framework.TestApplicationUtils;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramSelection;
import ghidra.test.TestEnv;
import ghidra.trace.model.breakpoint.TraceBreakpoint;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceSection;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.schedule.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class TutorialDebuggerScreenShots extends GhidraScreenShotGenerator
		implements AsyncTestUtils {
	protected static final String TUTORIAL_PATH =
		TestApplicationUtils.getInstallationDirectory() + "/GhidraDocs/GhidraClass/Debugger/";
	protected static final File TUTORIAL_DIR = new File(TUTORIAL_PATH);

	protected static final String TERMMINES_PATH = "/tmp/termmines";

	protected final ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

	protected ProgramManager programManager;
	protected CodeViewerService staticListingService;
	protected DebuggerWorkflowService workflowService;
	protected DebuggerModelService modelService;

	protected DebuggerModelFactory gdbFactory;

	protected final FlatDebuggerAPI flatDbg = new FlatDebuggerAPI() {
		@Override
		public GhidraState getState() {
			Navigatable nav = staticListingService.getNavigatable();
			return new GhidraState(tool, env.getProject(),
				nav.getProgram(), nav.getLocation(), nav.getSelection(), nav.getHighlight());
		}
	};

	@Override
	protected TestEnv newTestEnv() throws Exception {
		return new TestEnv("DebuggerCourse");
	}

	// TODO: Propose this replace waitForProgram
	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	protected void intoProject(DomainObject obj) {
		waitForDomainObject(obj);
		DomainFolder rootFolder = tool.getProject()
				.getProjectData()
				.getRootFolder();
		waitForCondition(() -> {
			try {
				rootFolder.createFile(obj.getName(), obj, monitor);
				return true;
			}
			catch (InvalidNameException | CancelledException e) {
				throw new AssertionError(e);
			}
			catch (IOException e) {
				// Usually "object is busy". Try again.
				return false;
			}
		});
	}

	@Override
	public void prepareTool() {
		tool = env.launchTool("Debugger");
	}

	@Override
	public void loadProgram() throws Exception {
		loadProgram("termmines");
		try (Transaction tx = program.openTransaction("Set exe path")) {
			program.setExecutablePath(TERMMINES_PATH);
		}
		intoProject(program);
	}

	@Override
	public void saveOrDisplayImage(String name) {
		if (TUTORIAL_DIR.exists()) {
			TUTORIAL_DIR.mkdirs();
		}
		name = name.substring("test".length());
		finished(TUTORIAL_DIR, name + ".png");
	}

	protected void enableBot(Class<? extends DebuggerBot> botCls) {
		Set<DebuggerBot> bots = workflowService.getAllBots()
				.stream()
				.filter(b -> botCls.isInstance(b))
				.map(b -> botCls.cast(b))
				.collect(Collectors.toSet());
		workflowService.enableBots(bots);
	}

	protected CodeViewerService getStaticListingService() {
		for (CodeViewerService viewer : tool.getServices(CodeViewerService.class)) {
			if (viewer instanceof DebuggerListingService) {
				continue;
			}
			return viewer;
		}
		return null;
	}

	@Before
	public void setUpDebugger() throws Throwable {
		ResourceFile termminesRsrc = Application.getModuleDataFile("TestResources", "termmines");
		File termmines = new File(TERMMINES_PATH);
		try {
			Files.copy(termminesRsrc.getFile(false).toPath(), termmines.toPath());
		}
		catch (FileNotFoundException e) {
			Msg.warn(this, "Could not update " + TERMMINES_PATH);
		}
		catch (FileAlreadyExistsException e) {
			Files.delete(termmines.toPath());
			Files.copy(termminesRsrc.getFile(false).toPath(), termmines.toPath());
		}
		termmines.setExecutable(true);

		programManager = tool.getService(ProgramManager.class);
		staticListingService = getStaticListingService();

		// This is a front-end plugin. We have to configure it.
		workflowService = tool.getService(DebuggerWorkflowService.class);
		enableBot(MapModulesDebuggerBot.class);
		enableBot(DisassembleAtPcDebuggerBot.class);
		enableBot(ShowInterpreterDebuggerBot.class);

		modelService = tool.getService(DebuggerModelService.class);
		gdbFactory = modelService.getModelFactories()
				.stream()
				.filter(f -> "gdb".equals(f.getBrief()))
				.findAny()
				.get();

		@SuppressWarnings("unchecked")
		Property<String> gdbPathProp =
			(Property<String>) gdbFactory.getOptions().get("GDB launch command");
		gdbPathProp.setValue(DummyProc.which("gdb"));
	}

	@Test
	public void testGettingStarted_ToolWSpecimen() {
		captureToolWindow(1920, 1080);
	}

	protected void launchProgramInGdb(String extraArgs) throws Throwable {
		DebuggerProgramLaunchOffer offer = modelService.getProgramLaunchOffers(program)
				.filter(o -> "IN-VM GDB".equals(o.getConfigName()))
				.findFirst()
				.get();
		LaunchConfigurator config = new LaunchConfigurator() {
			@Override
			public Map<String, ?> configureLauncher(TargetLauncher launcher,
					Map<String, ?> arguments, RelPrompt relPrompt) {
				if (extraArgs.length() == 0) {
					return arguments;
				}
				Map<String, Object> adjusted = new HashMap<>(arguments);
				TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS.adjust(adjusted,
					c -> c + " " + extraArgs);
				return adjusted;
			}
		};
		LaunchResult result = waitOn(offer.launchProgram(monitor, PromptMode.NEVER, config));
		if (result.exception() != null) {
			throw result.exception();
		}
	}

	protected void launchProgramInGdb() throws Throwable {
		launchProgramInGdb("");
	}

	@Test
	public void testGettingStarted_DisassemblyAfterLaunch() throws Throwable {
		launchProgramInGdb();

		captureToolWindow(1920, 1080);
	}

	@Test
	public void testBreakpoints_EmptyAfterLaunch() throws Throwable {
		launchProgramInGdb();

		tool.setSize(1920, 1080);
		captureProvider(DebuggerBreakpointsProvider.class);
	}

	protected void placeBreakpointsSRandRand() throws Throwable {
		assertTrue(flatDbg.execute("break srand"));
		assertTrue(flatDbg.execute("break rand"));
		waitForCondition(() -> flatDbg.getAllBreakpoints().size() == 2);
	}

	protected void placeBreakpointsRand() throws Throwable {
		assertTrue(flatDbg.execute("break rand"));
		waitForCondition(() -> flatDbg.getAllBreakpoints().size() == 1);
	}

	@Test
	public void testBreakpoints_PopAfterSRandRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();

		tool.setSize(1920, 1080);
		captureProvider(DebuggerBreakpointsProvider.class);
	}

	protected Address navigateToBreakpoint(String comment) {
		TraceBreakpoint bp = flatDbg.getAllBreakpoints()
				.stream()
				.flatMap(l -> l.getTraceBreakpoints().stream())
				.filter(l -> comment.equals(l.getComment()))
				.findAny()
				.get();
		Address dynAddr = bp.getMinAddress();
		flatDbg.goToDynamic(dynAddr);
		return dynAddr;
	}

	@Test
	public void testBreakpoints_MissingModuleNote() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();
		navigateToBreakpoint("srand");

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerConsoleProvider.class);
	}

	protected Program importModule(TraceModule module) throws Throwable {
		Program prog = null;
		try {
			MessageLog log = new MessageLog();
			LoadResults<Program> result = AutoImporter.importByUsingBestGuess(
				new File(module.getName()), env.getProject(), "/", this, log, monitor);
			result.save(env.getProject(), this, log, monitor);
			prog = result.getPrimaryDomainObject();
			GhidraProgramUtilities.markProgramNotToAskToAnalyze(prog);
			programManager.openProgram(prog);
		}
		finally {
			if (prog != null) {
				prog.release(this);
			}
		}
		return prog;
	}

	protected void analyze(Program prog) {
		DockingActionIf actAutoAnalyze = Unique.assertOne(getActionsByOwnerAndName(tool,
			PluginUtils.getPluginNameFromClass(AutoAnalysisPlugin.class), "Auto Analyze"));
		performAction(actAutoAnalyze);
	}

	protected TraceModule getModuleContaining(Address dynAddr) {
		return Unique.assertOne(flatDbg.getCurrentTrace()
				.getModuleManager()
				.getModulesAt(flatDbg.getCurrentSnap(), dynAddr));
	}

	protected void disassembleSymbol(Program prog, String name) {
		for (Symbol sym : prog.getSymbolTable().getLabelOrFunctionSymbols(name, null)) {
			tool.executeBackgroundCommand(new DisassembleCommand(sym.getAddress(), null, true),
				prog);
		}
		waitForTasks(600 * 1000);
	}

	@Test
	public void testBreakpoints_SyncedAfterImportLibC() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();
		showProvider(DebuggerBreakpointsProvider.class);
		Address dynAddr = navigateToBreakpoint("srand");
		TraceModule modLibC = getModuleContaining(dynAddr);
		Program progLibC = importModule(modLibC);
		waitForCondition(() -> flatDbg.translateDynamicToStatic(dynAddr) != null);
		disassembleSymbol(progLibC, "srand");
		// Just to be sure.
		goTo(tool, progLibC, flatDbg.translateDynamicToStatic(dynAddr));

		captureToolWindow(1920, 1080);
	}

	@Test
	public void testBreakpoints_SeedValueAfterBreakSRand() throws Throwable {
		addPlugin(tool, VariableValueHoverPlugin.class);

		launchProgramInGdb();
		placeBreakpointsSRandRand();
		showProvider(DecompilerProvider.class);
		Address dynAddr = navigateToBreakpoint("srand");
		TraceModule modLibC = getModuleContaining(dynAddr);
		Program progLibC = importModule(modLibC);
		waitForCondition(() -> flatDbg.translateDynamicToStatic(dynAddr) != null);
		disassembleSymbol(progLibC, "srand");
		Address stAddr = flatDbg.translateDynamicToStatic(dynAddr);
		// Just to be sure.
		goTo(tool, progLibC, stAddr);
		flatDbg.resume();

		Function funSRand = progLibC.getFunctionManager().getFunctionAt(stAddr);

		runSwing(() -> tool.setSize(1920, 1080));

		DecompilerProvider dProvider = waitForComponentProvider(DecompilerProvider.class);
		DecompilerPanel dPanel = dProvider.getDecompilerPanel();
		HoverLocation loc = StackUnwinderTest.findTokenLocation(dPanel, funSRand, "param_1",
			"void srand(ulong param_1)");
		runSwing(() -> dPanel.goToToken(loc.token()));
		FieldPanel fieldPanel = dPanel.getFieldPanel();
		Rectangle rect = fieldPanel.getCursorBounds();
		MouseEvent event =
			new MouseEvent(fieldPanel, 0, System.currentTimeMillis(), 0, rect.x, rect.y, 0, false);
		fieldPanel.getHoverHandler().mouseHovered(event);
		waitForSwing();
		sleep(500); // Give time for GDB to respond async

		captureProviderWithScreenShot(dProvider);
	}

	@Test
	public void testState_ListingAfterCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		flatDbg.resume();
		flatDbg.stepOut();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testState_ListingStackAfterCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		flatDbg.resume();
		flatDbg.stepOut();

		DebuggerListingService listingService = tool.getService(DebuggerListingService.class);
		listingService.setTrackingSpec(SPLocationTrackingSpec.INSTANCE);

		sleep(1000);

		tool.execute(new UnwindStackCommand(tool, flatDbg.getCurrentDebuggerCoordinates()),
			flatDbg.getCurrentTrace());
		waitForTasks();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testState_BytesStackAfterCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		flatDbg.resume();
		flatDbg.stepOut();

		DebuggerMemoryBytesProvider bytesProvider = showProvider(DebuggerMemoryBytesProvider.class);
		bytesProvider.setTrackingSpec(SPLocationTrackingSpec.INSTANCE);

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerMemoryBytesProvider.class);
	}

	@Test
	public void testState_RegistersAfterCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		flatDbg.resume();
		flatDbg.stepOut();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerRegistersProvider.class);
	}

	@Test
	public void testState_WatchesInCallSRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();
		flatDbg.resume();

		DebuggerWatchesService watchesService = tool.getService(DebuggerWatchesService.class);
		watchesService.addWatch("RDI");
		WatchRow watchRetPtr = watchesService.addWatch("*:8 RSP");
		watchRetPtr.setDataType(
			new PointerTypedefBuilder(VoidDataType.dataType, 8, null).addressSpace("ram").build());

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerWatchesProvider.class);
	}

	@Test
	public void testNavigation_ThreadsInCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		flatDbg.resume();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerThreadsProvider.class);
	}

	@Test
	public void testNavigation_StackInCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsRand();
		Address dynAddr = navigateToBreakpoint("rand");
		TraceModule modLibC = getModuleContaining(dynAddr);
		importModule(modLibC);
		waitForCondition(() -> flatDbg.translateDynamicToStatic(dynAddr) != null);
		flatDbg.resume();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerStackProvider.class);
	}

	@Test
	public void testNavigation_TimeAfterCallSRandCallRand() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();
		flatDbg.resume(); // srand
		flatDbg.resume(); // rand.1
		flatDbg.stepOut();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerTimeProvider.class);
	}

	@Test
	public void testNavigation_DialogCompareTimes() throws Throwable {
		launchProgramInGdb(); // main
		placeBreakpointsRand();
		Address pc = flatDbg.getProgramCounter();
		long snapA = flatDbg.getCurrentSnap();
		TraceModule modTermmines = Unique.assertOne(flatDbg.getCurrentTrace()
				.getModuleManager()
				.getModulesAt(snapA, pc));
		TraceSection secTermminesData = modTermmines.getSectionByName(".data");
		flatDbg.readMemory(secTermminesData.getStart(),
			(int) secTermminesData.getRange().getLength(), monitor);

		flatDbg.resume(); // rand.1
		flatDbg.readMemory(secTermminesData.getStart(),
			(int) secTermminesData.getRange().getLength(), monitor);

		performAction("Compare",
			PluginUtils.getPluginNameFromClass(DebuggerTraceViewDiffPlugin.class), false);
		DebuggerTimeSelectionDialog timeDialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		timeDialog.setScheduleText(TraceSchedule.snap(snapA).toString());
		captureDialog(timeDialog);
	}

	@Test
	public void testNavigation_CompareTimes() throws Throwable {
		launchProgramInGdb("-M 15"); // main
		placeBreakpointsRand();
		Address pc = flatDbg.getProgramCounter();
		long snapA = flatDbg.getCurrentSnap();
		TraceModule modTermmines = Unique.assertOne(flatDbg.getCurrentTrace()
				.getModuleManager()
				.getModulesAt(snapA, pc));
		TraceSection secTermminesData = modTermmines.getSectionByName(".data");
		flatDbg.readMemory(secTermminesData.getStart(),
			(int) secTermminesData.getRange().getLength(), monitor);

		flatDbg.resume(); // rand.1
		flatDbg.waitForBreak(1000, TimeUnit.MILLISECONDS);
		flatDbg.readMemory(secTermminesData.getStart(),
			(int) secTermminesData.getRange().getLength(), monitor);

		performAction("Compare",
			PluginUtils.getPluginNameFromClass(DebuggerTraceViewDiffPlugin.class), false);
		DebuggerTimeSelectionDialog timeDialog =
			waitForDialogComponent(DebuggerTimeSelectionDialog.class);
		runSwing(() -> timeDialog.setScheduleText(TraceSchedule.snap(snapA).toString()));
		runSwing(() -> timeDialog.okCallback());

		DockingActionIf actionNextDiff = waitForValue(() -> {
			try {
				return Unique.assertOne(getActionsByOwnerAndName(tool,
					PluginUtils.getPluginNameFromClass(DebuggerTraceViewDiffPlugin.class),
					"Next Difference"));
			}
			catch (Throwable e) {
				return null;
			}
		});
		waitForCondition(() -> actionNextDiff.isEnabled());
		flatDbg.goToDynamic(secTermminesData.getStart());
		performAction(actionNextDiff);

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testMemoryMap_RegionsAfterLaunch() throws Throwable {
		launchProgramInGdb();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerRegionsProvider.class);
	}

	@Test
	public void testMemoryMap_ModulesAfterLaunch() throws Throwable {
		launchProgramInGdb();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerModulesProvider.class);
	}

	@Test
	public void testMemoryMap_StaticMappingAfterLaunch() throws Throwable {
		launchProgramInGdb();
		placeBreakpointsSRandRand();
		showProvider(DebuggerStaticMappingProvider.class);
		Address dynAddr = navigateToBreakpoint("srand");
		TraceModule modLibC = getModuleContaining(dynAddr);
		importModule(modLibC);
		waitForCondition(() -> flatDbg.translateDynamicToStatic(dynAddr) != null);

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerStaticMappingProvider.class);
	}

	@Test
	public void testMemoryMap_CopyNcursesInto() throws Throwable {
		launchProgramInGdb();
		TraceModule modNcurses = flatDbg.getCurrentTrace()
				.getModuleManager()
				.getAllModules()
				.stream()
				.filter(m -> m.getName().contains("ncurses"))
				.findAny()
				.get();
		DebuggerListingService listings = tool.getService(DebuggerListingService.class);
		runSwing(() -> listings
				.setCurrentSelection(new ProgramSelection(new AddressSet(modNcurses.getRange()))));
		performAction("Copy Into New Program",
			PluginUtils.getPluginNameFromClass(DebuggerCopyActionsPlugin.class), false);
		captureDialog(DebuggerCopyIntoProgramDialog.class);
	}

	@Test
	public void testRemoteTargets_GdbOverSsh() throws Throwable {
		performAction("Connect", PluginUtils.getPluginNameFromClass(DebuggerTargetsPlugin.class),
			false);
		DebuggerConnectDialog dialog = waitForDialogComponent(DebuggerConnectDialog.class);
		runSwing(() -> dialog.setFactoryByBrief("gdb via SSH"));

		captureDialog(dialog);
	}

	@Test
	public void testRemoteTargets_Gadp() throws Throwable {
		performAction("Connect", PluginUtils.getPluginNameFromClass(DebuggerTargetsPlugin.class),
			false);
		DebuggerConnectDialog dialog = waitForDialogComponent(DebuggerConnectDialog.class);
		runSwing(() -> dialog.setFactoryByBrief("Ghidra debug agent (GADP)"));

		captureDialog(dialog);
	}

	protected Function findCommandLineParser() throws Throwable {
		for (Data data : program.getListing().getDefinedData(true)) {
			Object value = data.getValue();
			if (!(value instanceof String str) || !str.startsWith("Usage: ")) {
				continue;
			}
			for (Reference refToUsage : data.getReferenceIteratorTo()) {
				Address from = refToUsage.getFromAddress();
				Function function = program.getFunctionManager().getFunctionContaining(from);
				if (function != null) {
					return function;
				}
			}
		}
		throw new AssertionError("Cannot find command-line parsing function");
	}

	protected CodeViewerProvider getCodeViewerProvider() {
		return (CodeViewerProvider) staticListingService.getNavigatable(); // HACK
	}

	protected void goToStaticUntilContext(Address address) {
		CodeViewerProvider provider = getCodeViewerProvider();
		waitForCondition(() -> {
			goTo(tool, program, address);
			runSwing(() -> provider.contextChanged());
			return provider.getActionContext(null) instanceof ProgramLocationActionContext;
		});
	}

	protected void emulateCommandLineParser() throws Throwable {
		Function function = findCommandLineParser();
		goToStaticUntilContext(function.getEntryPoint());
		performAction(EmulateProgramAction.NAME,
			PluginUtils.getPluginNameFromClass(DebuggerEmulationServicePlugin.class),
			getCodeViewerProvider(), true);

	}

	@Test
	public void testEmulation_LazyStaleListing() throws Throwable {
		emulateCommandLineParser();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testEmulation_ListingAfterResume() throws Throwable {
		emulateCommandLineParser();

		DebuggerListingProvider listing = getProvider(DebuggerListingProvider.class);
		listing.setAutoReadMemorySpec(
			AutoReadMemorySpec.fromConfigName(LoadEmulatorAutoReadMemorySpec.CONFIG_NAME));
		EmulationResult result = flatDbg.getEmulationService()
				.run(flatDbg.getCurrentPlatform(), flatDbg.getCurrentEmulationSchedule(), monitor,
					Scheduler.oneThread(flatDbg.getCurrentThread()));
		flatDbg.getTraceManager().activateTime(result.schedule());

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	protected void addWatchesForCmdline() throws Throwable {
		DebuggerWatchesService watchesService = tool.getService(DebuggerWatchesService.class);
		watchesService.addWatch("RSP");
		watchesService.addWatch("RDI");
		watchesService.addWatch("RSI");

		watchesService.addWatch("*:8 (RSI + 0)");
		watchesService.addWatch("*:8 (RSI + 8)");
		watchesService.addWatch("*:8 (RSI + 16)");

		watchesService.addWatch("*:30 (*:8 (RSI + 0))")
				.setDataType(TerminatedStringDataType.dataType);
		watchesService.addWatch("*:30 (*:8 (RSI + 8))")
				.setDataType(TerminatedStringDataType.dataType);
		watchesService.addWatch("*:30 (*:8 (RSI + 16))")
				.setDataType(TerminatedStringDataType.dataType);
	}

	@Test
	public void testEmulation_WatchesForCmdline() throws Throwable {
		emulateCommandLineParser();
		addWatchesForCmdline();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerWatchesProvider.class);
	}

	protected void activateCmdlinePatchedSchedule() throws Throwable {
		TracePlatform platform = flatDbg.getCurrentPlatform();
		Address forArgv0 = platform.getAddressFactory().getAddress("00001018");
		Address forArgv1 = forArgv0.add("termmines\0".length());
		Address forArgv2 = forArgv1.add("-s\0".length());
		List<String> sleigh = new ArrayList<>();
		sleigh.add("RDI=3");
		sleigh.add("RSI=0x1000");
		sleigh.addAll(PatchStep.generateSleigh(platform.getLanguage(),
			forArgv0, "termmines\0".getBytes()));
		sleigh.addAll(PatchStep.generateSleigh(platform.getLanguage(),
			forArgv1, "-s\0".getBytes()));
		sleigh.addAll(PatchStep.generateSleigh(platform.getLanguage(),
			forArgv2, "Advanced\0".getBytes()));
		sleigh.add("*:8 (RSI + 0) = 0x" + forArgv0);
		sleigh.add("*:8 (RSI + 8) = 0x" + forArgv1);
		sleigh.add("*:8 (RSI + 16) = 0x" + forArgv2);
		TraceSchedule schedule = flatDbg.getCurrentEmulationSchedule();
		schedule = schedule.patched(flatDbg.getCurrentThread(), platform.getLanguage(), sleigh);

		flatDbg.getTraceManager().activateTime(schedule);
		getProvider(DebuggerWatchesProvider.class).waitEvaluate(1000);
	}

	@Test
	public void testEmulation_WatchesForCmdlineSet() throws Throwable {
		emulateCommandLineParser();
		addWatchesForCmdline();
		activateCmdlinePatchedSchedule();

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerWatchesProvider.class);
	}

	@Test
	public void testEmulation_ListingForCmdlineSet() throws Throwable {
		emulateCommandLineParser();
		activateCmdlinePatchedSchedule();

		Address addrArgv = flatDbg.getCurrentPlatform().getAddressFactory().getAddress("00001000");

		TraceProgramView view = flatDbg.getCurrentView();
		waitForCondition(() -> view.getSnap() != 0);
		try (Transaction tx = view.openTransaction("Place units")) {
			Listing listing = view.getListing();
			Data datArgv =
				listing.createData(addrArgv, new ArrayDataType(PointerDataType.dataType, 3, 8));
			Address forArgv0 = (Address) datArgv.getComponent(0).getValue();
			Address forArgv1 = (Address) datArgv.getComponent(1).getValue();
			Address forArgv2 = (Address) datArgv.getComponent(2).getValue();

			listing.createData(forArgv0, TerminatedStringDataType.dataType);
			listing.createData(forArgv1, TerminatedStringDataType.dataType);
			listing.createData(forArgv2, TerminatedStringDataType.dataType);
		}
		flatDbg.goToDynamic("00001010");

		runSwing(() -> tool.setSize(1920, 1080));
		captureProvider(DebuggerListingProvider.class);
	}

	@Test
	public void testEmulation_PcodeStepper() throws Throwable {
		runSwing(() -> tool.setSize(1920, 1080));
		addPlugin(tool, DebuggerPcodeStepperPlugin.class);
		emulateCommandLineParser();
		flatDbg.stepEmuPcodeOp(1, monitor);

		captureProvider(DebuggerPcodeStepperProvider.class);
	}
}
