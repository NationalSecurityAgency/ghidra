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

import static org.junit.Assert.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import db.Transaction;
import docking.ActionContext;
import docking.DefaultActionContext;
import docking.action.ActionContextProvider;
import docking.action.DockingActionIf;
import docking.widgets.table.DynamicTableColumn;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.Unique;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.debug.gui.action.*;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.gui.model.columns.TraceValueObjectPropertyColumn;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.*;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.dbg.model.AbstractTestTargetRegisterBank;
import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.dbg.target.*;
import ghidra.dbg.testutil.DebuggerModelTestUtils;
import ghidra.docking.settings.SettingsImpl;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.InvalidNameException;
import ghidra.util.datastruct.ListenerMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;

public abstract class AbstractGhidraHeadedDebuggerGUITest
		extends AbstractGhidraHeadedIntegrationTest implements DebuggerModelTestUtils {

	public static final String LANGID_TOYBE64 = "Toy:BE:64:default";

	public static class TestDebuggerTargetTraceMapper extends DefaultDebuggerTargetTraceMapper {
		// TODO: Instantiate this in an opinion / offer
		public TestDebuggerTargetTraceMapper(TargetObject target)
				throws LanguageNotFoundException, CompilerSpecNotFoundException {
			super(target, new LanguageID(LANGID_TOYBE64), new CompilerSpecID("default"), Set.of());
		}

		@Override
		protected DebuggerMemoryMapper createMemoryMapper(TargetMemory memory) {
			return new DefaultDebuggerMemoryMapper(language, memory.getModel());
		}

		@Override
		protected DebuggerRegisterMapper createRegisterMapper(
				TargetRegisterContainer registers) {
			return new DefaultDebuggerRegisterMapper(cSpec, registers, true);
		}
	}

	protected static void assertNoElement(Supplier<?> supplier) {
		// Give the element a chance to appear
		try {
			Thread.sleep(DEFAULT_WAIT_DELAY);
		}
		catch (InterruptedException e1) {
			// Whatever
		}
		try {
			Object value = supplier.get();
			fail("Expected NoSuchElementException. Got " + value);
		}
		catch (NoSuchElementException e) {
			// Good
		}
	}

	protected static void assertTypeEquals(DataType expected, DataType actual) {
		if (expected == null && actual == null) {
			return;
		}
		if (expected == null || actual == null) {
			assertEquals(expected, actual);
		}
		if (!actual.isEquivalent(expected) || expected.isEquivalent(actual)) {
			return;
		}
		assertEquals(expected, actual);
	}

	/**
	 * Works like {@link #waitForValue(Supplier)}, except this caches {@link NoSuchElementException}
	 * and tries again.
	 * 
	 * @param <T> the type of object to wait for
	 * @param supplier the supplier of the object
	 * @return the object
	 */
	protected static <T> T waitForElement(Supplier<T> supplier) {
		return waitForValue(() -> {
			try {
				return supplier.get();
			}
			catch (NoSuchElementException e) {
				return null;
			}
		});
	}

	protected static void waitForNoElement(Supplier<?> supplier) {
		waitForValue(() -> {
			try {
				supplier.get();
				return null;
			}
			catch (NoSuchElementException e) {
				return new Object();
			}
		});
	}

	/**
	 * This is so gross
	 * 
	 * @param lockable
	 */
	protected void waitForLock(DomainObject lockable) {
		waitForPass(() -> {
			assertTrue(lockable.lock(null));
			lockable.unlock();
		});
	}

	/**
	 * Get an address in the trace's default space
	 * 
	 * @param trace the trace
	 * @param offset the byte offset in the default space
	 * @return the address
	 */
	protected static Address addr(Trace trace, long offset) {
		return trace.getBaseAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Get an address in the program's default space
	 * 
	 * @param program the program
	 * @param offset the byte offset in the default space
	 * @return the address
	 */
	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	/**
	 * Get an address range in the trace's default space
	 * 
	 * @param program the program
	 * @param min the min byte offset in the default space
	 * @param max the max byte offset in the default space
	 * @return the address range
	 */
	protected static AddressRange rng(Program program, long min, long max) {
		return new AddressRangeImpl(addr(program, min), addr(program, max));
	}

	protected static AddressSetView set(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange rng : ranges) {
			set.add(rng);
		}
		return set;
	}

	public static Language getToyBE64Language() {
		try {
			return DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(LANGID_TOYBE64));
		}
		catch (LanguageNotFoundException e) {
			throw new AssertionError("Why is the Toy language missing?", e);
		}
	}

	protected static TargetBreakpointSpecContainer getBreakpointContainer(TraceRecorder r) {
		return waitFor(() -> Unique.assertAtMostOne(r.collectBreakpointContainers(null)),
			"No container");
	}

	// TODO: Propose this replace waitForProgram
	public static void waitForDomainObject(DomainObject object) {
		object.flushEvents();
		waitForSwing();
	}

	public interface ExRunnable {
		void run() throws Throwable;
	}

	protected static Runnable noExc(ExRunnable runnable) {
		return () -> {
			try {
				runnable.run();
			}
			catch (Throwable e) {
				throw new AssertionError(e);
			}
		};
	}

	public static void waitForPass(Runnable runnable) {
		AtomicReference<AssertionError> lastError = new AtomicReference<>();
		waitForCondition(() -> {
			try {
				runnable.run();
				return true;
			}
			catch (AssertionError e) {
				lastError.set(e);
				return false;
			}
		}, () -> lastError.get().getMessage());
	}

	public static <T> T waitForPass(Supplier<T> supplier) {
		var locals = new Object() {
			AssertionError lastError;
			T value;
		};
		waitForCondition(() -> {
			try {
				locals.value = supplier.get();
				return true;
			}
			catch (AssertionError e) {
				locals.lastError = e;
				return false;
			}
		}, () -> locals.lastError.getMessage());
		return locals.value;
	}

	protected static Set<String> getMenuElementsText(MenuElement menu) {
		Set<String> result = new HashSet<>();
		for (MenuElement sub : menu.getSubElements()) {
			Component comp = sub.getComponent();
			if (comp instanceof JPopupMenu) {
				return getMenuElementsText(sub);
			}
			JMenuItem item = (JMenuItem) sub.getComponent();
			result.add(item.getText());
		}
		return result;
	}

	protected static Set<String> getMenuElementsText() {
		MenuElement[] sel = runSwing(() -> MenuSelectionManager.defaultManager().getSelectedPath());
		if (sel == null || sel.length == 0) {
			return Set.of();
		}
		MenuElement last = sel[sel.length - 1];
		return getMenuElementsText(last);
	}

	protected static Set<String> intersection(Collection<String> a, Collection<String> b) {
		Set<String> result = new LinkedHashSet<>(a);
		result.retainAll(b);
		return Set.copyOf(result);
	}

	protected static void assertMenu(Set<String> cares, Set<String> expectedTexts) {
		waitForPass(() -> {
			assertEquals(expectedTexts, intersection(cares, getMenuElementsText()));
		});
	}

	protected static MenuElement getSubMenuElementByText(String text) {
		MenuElement[] sel = runSwing(() -> MenuSelectionManager.defaultManager().getSelectedPath());
		if (sel == null || sel.length == 0) {
			throw new NoSuchElementException("No menu is active");
		}
		MenuElement last = sel[sel.length - 1];
		for (MenuElement sub : last.getSubElements()) {
			JMenuItem item = (JMenuItem) sub.getComponent();
			if (text.equals(item.getText())) {
				return sub;
			}
		}
		throw new NoSuchElementException("No item with text " + text);
	}

	protected static void assertSubMenu(MenuElement sub, Set<String> cares,
			Set<String> expectedTexts) {
		waitForPass(() -> {
			assertEquals(expectedTexts, intersection(cares, getMenuElementsText(sub)));
		});
	}

	/**
	 * Find the sub menu item of the current selection by text
	 * 
	 * Note that if the desired item is at the same level as the currently selected item, this
	 * method will not find it. It searches the sub menu of the currently selected item.
	 * 
	 * @param text the text
	 * @return the found item
	 * @throws NoSuchElementException if the desired item is not found
	 */
	protected static JMenuItem getSubMenuItemByText(String text) {
		MenuElement sub = getSubMenuElementByText(text);
		return (JMenuItem) sub.getComponent();
	}

	/**
	 * Activate via mouse the sub menu item of the current selection by text
	 * 
	 * @param text the text on the item to click
	 * @throws AWTException
	 * @throws NoSuchElementException if no item with the given text is found
	 */
	protected static void clickSubMenuItemByText(String text) throws Exception {
		JMenuItem item = getSubMenuItemByText(text);
		waitFor(() -> item.isShowing());

		Point isl = item.getLocationOnScreen();
		Rectangle b = item.getBounds();
		Point m = new Point(isl.x + b.width / 2, isl.y + b.height / 2);

		clickMouse(MouseEvent.BUTTON1, m);
	}

	protected static void pressEscape() throws AWTException {
		Robot robot = new Robot();
		robot.keyPress(KeyEvent.VK_ESCAPE);
		robot.keyRelease(KeyEvent.VK_ESCAPE);
	}

	protected static Point getViewportPosition(Component comp) {
		Component parent = comp.getParent();
		if (!(parent instanceof JViewport)) {
			return new Point(0, 0);
		}
		JViewport viewport = (JViewport) parent;
		return viewport.getViewPosition();
	}

	protected static void clickMouse(int button, Point m) throws Exception {
		Robot robot = new Robot();
		robot.mouseMove(m.x, m.y);
		int mask = InputEvent.getMaskForButton(button);
		robot.mousePress(mask);
		robot.mouseRelease(mask);
	}

	protected static void clickListItem(JList<?> list, int index, int button) throws Exception {
		list.ensureIndexIsVisible(index);
		waitForSwing();

		Rectangle b = list.getCellBounds(index, index);
		Point lsl = list.getLocationOnScreen();
		Point vp = getViewportPosition(list);
		Point m = new Point(lsl.x + b.x + b.width / 2 - vp.x, lsl.y + b.y + b.height / 2 - vp.y);

		clickMouse(button, m);
	}

	protected static void clickTreeNode(GTree tree, GTreeNode node, int button) throws Exception {
		TreePath path = node.getTreePath();
		tree.scrollPathToVisible(path);
		waitForSwing();

		Rectangle b = tree.getPathBounds(path);
		Point tsl = tree.getLocationOnScreen();
		Point vp = tree.getViewPosition();
		Point m = new Point(tsl.x + b.x + b.width / 2 - vp.x, tsl.y + b.y + b.height / 2 - vp.y);

		clickMouse(button, m);
	}

	protected static void clickTableCellWithButton(JTable table, int row, int col, int button)
			throws Exception {
		Rectangle b = table.getCellRect(row, col, false);
		table.scrollRectToVisible(b);
		waitForSwing();

		Point tsl = table.getLocationOnScreen();
		Point m = new Point(tsl.x + b.x + b.width / 2, tsl.y + b.y + b.height / 2);

		clickMouse(button, m);
	}

	protected static void assertListingBackgroundAt(Color expected, ListingPanel panel,
			Address addr, int yAdjust) throws AWTException, InterruptedException {
		ProgramLocation oneBack = new ProgramLocation(panel.getProgram(), addr.previous());
		runSwing(() -> panel.goTo(addr));
		runSwing(() -> panel.goTo(oneBack, false));
		waitForPass(() -> {
			Rectangle r = panel.getBounds();
			// Capture off screen, so that focus/stacking doesn't matter
			BufferedImage image = new BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB);
			Graphics g = image.getGraphics();
			try {
				runSwing(() -> panel.paint(g));
			}
			finally {
				g.dispose();
			}
			Point locP = panel.getLocationOnScreen();
			Point locFP = panel.getLocationOnScreen();
			locFP.translate(-locP.x, -locP.y);
			Rectangle cursor = panel.getCursorBounds();
			assertNotNull("Cannot get cursor bounds", cursor);
			Color actual = new Color(image.getRGB(locFP.x + cursor.x - 1,
				locFP.y + cursor.y + cursor.height * 3 / 2 + yAdjust));
			assertEquals(expected.getRGB(), actual.getRGB());
		});
	}

	protected static void assertDisabled(ActionContextProvider provider, DockingActionIf action) {
		ActionContext context = provider.getActionContext(null);
		assertFalse(action.isEnabledForContext(context));
	}

	protected static void assertEnabled(ActionContextProvider provider, DockingActionIf action) {
		ActionContext context = provider.getActionContext(null);
		assertTrue(action.isEnabledForContext(context));
	}

	protected static void performEnabledAction(ActionContextProvider provider,
			DockingActionIf action, boolean wait) {
		ActionContext context = waitForValue(() -> {
			ActionContext ctx = provider == null
					? new DefaultActionContext()
					: provider.getActionContext(null);
			if (!action.isEnabledForContext(ctx)) {
				return null;
			}
			return ctx;
		});
		performAction(action, context, wait);
	}

	protected static void goTo(ListingPanel listingPanel, ProgramLocation location) {
		waitForPass(() -> {
			runSwing(() -> listingPanel.goTo(location));
			ProgramLocation confirm = listingPanel.getCursorLocation();
			assertNotNull(confirm);
			assertEquals(location.getAddress(), confirm.getAddress());
		});
	}

	protected void select(Navigatable nav, Address min, Address max) {
		select(nav, new ProgramSelection(min, max));
	}

	protected void select(Navigatable nav, AddressSetView set) {
		select(nav, new ProgramSelection(set));
	}

	protected void select(Navigatable nav, ProgramSelection sel) {
		runSwing(() -> nav.setSelection(sel));
	}

	protected Object rowColVal(ValueRow row, DynamicTableColumn<ValueRow, ?, Trace> col) {
		if (col instanceof TraceValueObjectPropertyColumn<?> attrCol) {
			return attrCol.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool).getValue();
		}
		Object value = col.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool);
		return value;
	}

	protected <T> String rowColDisplay(ValueRow row, DynamicTableColumn<ValueRow, T, Trace> col) {
		T value = col.getValue(row, SettingsImpl.NO_SETTINGS, tb.trace, tool);
		return col.getColumnRenderer().getFilterString(value, SettingsImpl.NO_SETTINGS);
	}

	protected static LocationTrackingSpec getLocationTrackingSpec(String name) {
		return LocationTrackingSpecFactory.fromConfigName(name);
	}

	protected static AutoReadMemorySpec getAutoReadMemorySpec(String name) {
		return AutoReadMemorySpec.fromConfigName(name);
	}

	protected final AutoReadMemorySpec readNone =
		getAutoReadMemorySpec(NoneAutoReadMemorySpec.CONFIG_NAME);
	protected final AutoReadMemorySpec readVisible =
		getAutoReadMemorySpec(VisibleAutoReadMemorySpec.CONFIG_NAME);
	protected final AutoReadMemorySpec readVisROOnce =
		getAutoReadMemorySpec(VisibleROOnceAutoReadMemorySpec.CONFIG_NAME);

	protected TestEnv env;
	protected PluginTool tool;

	protected DebuggerModelService modelService;
	protected DebuggerModelServiceInternal modelServiceInternal;
	protected DebuggerTraceManagerService traceManager;
	protected ProgramManager programManager;

	protected TestDebuggerModelBuilder mb;
	protected ToyDBTraceBuilder tb;
	protected Program program;

	@Rule
	public TestName name = new TestName();
	@Rule
	public TestWatcher watcher = new TestWatcher() {
		@Override
		protected void succeeded(Description description) {
			if (description.isTest()) {
				ListenerMap.checkErr();
			}
		}
	};
	protected final ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

	protected void waitRecorder(TraceRecorder recorder) throws Throwable {
		if (recorder == null) {
			return;
		}
		try {
			waitOn(recorder.getTarget().getModel().flushEvents());
		}
		catch (RejectedExecutionException e) {
			// Whatever
		}
		try {
			waitOn(recorder.flushTransactions());
		}
		catch (RejectedExecutionException e) {
			// Whatever
		}
		waitForDomainObject(recorder.getTrace());
	}

	@Before
	public void setUp() throws Exception {
		ListenerMap.clearErr();
		env = new TestEnv();
		tool = env.getTool();

		DebuggerModelServiceProxyPlugin modelPlugin =
			addPlugin(tool, DebuggerModelServiceProxyPlugin.class);
		modelService = tool.getService(DebuggerModelService.class);
		assertEquals(modelPlugin, modelService);
		modelServiceInternal = modelPlugin;

		addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		traceManager = tool.getService(DebuggerTraceManagerService.class);

		programManager = tool.getService(ProgramManager.class);

		env.showTool();

		// Need this for the factory
		mb = new TestDebuggerModelBuilder();
	}

	@After
	public void tearDown() {
		waitForTasks();
		runSwing(() -> {
			if (traceManager == null) {
				return;
			}
			traceManager.setSaveTracesByDefault(false);
		});

		if (tb != null) {
			if (traceManager != null && traceManager.getOpenTraces().contains(tb.trace)) {
				traceManager.closeTrace(tb.trace);
			}
			tb.close();
		}

		if (mb != null) {
			if (mb.testModel != null) {
				modelService.removeModel(mb.testModel);
				for (TraceRecorder recorder : modelService.getTraceRecorders()) {
					recorder.stopRecording();
				}
			}
		}

		if (program != null) {
			programManager.closeAllPrograms(true);
			program.release(this);
		}

		waitForTasks();

		env.dispose();
	}

	protected void createTestModel() throws Exception {
		mb.createTestModel();
		modelService.addModel(mb.testModel);
	}

	protected void populateTestModel() throws Throwable {
		mb.createTestProcessesAndThreads();
		// NOTE: Test mapper uses TOYBE64
		mb.testProcess1.regs.addRegistersFromLanguage(getToyBE64Language(),
			Register::isBaseRegister);
		mb.createTestThreadRegisterBanks();
		mb.testProcess1.addRegion(".text", mb.rng(0x00400000, 0x00401000), "rx");
		mb.testProcess1.addRegion(".data", mb.rng(0x00600000, 0x00601000), "rw");
	}

	protected TargetObject chooseTarget() {
		return mb.testProcess1;
	}

	protected TraceRecorder recordAndWaitSync() throws Throwable {
		createTestModel();
		populateTestModel();

		TargetObject target = chooseTarget();
		TraceRecorder recorder = modelService.recordTarget(target,
			createTargetTraceMapper(target), ActionSource.AUTOMATIC);

		waitRecorder(recorder);
		return recorder;
	}

	protected void nop() {
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

	protected void createSnaplessTrace(String langID) throws IOException {
		tb = new ToyDBTraceBuilder("dynamic-" + name.getMethodName(), langID);
	}

	protected void createSnaplessTrace() throws IOException {
		createSnaplessTrace(LANGID_TOYBE64);
	}

	protected void addSnapshot(String desc) throws IOException {
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getTimeManager().createSnapshot(desc);
		}
	}

	protected void createTrace(String langID) throws IOException {
		createSnaplessTrace(langID);
		addSnapshot("First snap");
	}

	protected void createTrace() throws IOException {
		createTrace(LANGID_TOYBE64);
	}

	protected void useTrace(Trace trace) {
		tb = new ToyDBTraceBuilder(trace);
	}

	protected DebuggerTargetTraceMapper createTargetTraceMapper(TargetObject target)
			throws Exception {
		return new TestDebuggerTargetTraceMapper(target) {
			@Override
			public TraceRecorder startRecording(DebuggerModelServicePlugin service, Trace trace) {
				useTrace(trace);
				return super.startRecording(service, trace);
			}
		};
	}

	protected void createAndOpenTrace(String langID) throws IOException {
		createTrace(langID);
		traceManager.openTrace(tb.trace);
	}

	protected void createAndOpenTrace() throws IOException {
		createAndOpenTrace(LANGID_TOYBE64);
	}

	protected String getProgramName() {
		return "static-" + getClass().getCanonicalName() + "." + name.getMethodName();
	}

	protected void createProgramFromTrace(Trace trace) throws IOException {
		createProgram(trace.getBaseLanguage(), trace.getBaseCompilerSpec());
	}

	protected void createProgramFromTrace() throws IOException {
		createProgramFromTrace(tb.trace);
	}

	protected void createProgram(Language lang, CompilerSpec cSpec) throws IOException {
		program = new ProgramDB(getProgramName(), lang, cSpec, this);
	}

	protected void createProgram(Language lang) throws IOException {
		createProgram(lang, lang.getDefaultCompilerSpec());
	}

	protected void createProgram() throws IOException {
		createProgram(getToyBE64Language());
	}

	protected void createAndOpenProgramFromTrace() throws IOException {
		createProgramFromTrace();
		programManager.openProgram(program);
	}

	protected void createAndOpenProgramWithExePath(String path) throws IOException {
		Language lang = getToyBE64Language();
		program = new ProgramDB("static-" + name.getMethodName(), lang,
			lang.getDefaultCompilerSpec(), this);
		try (Transaction tx = program.openTransaction("Set Executable Path")) {
			program.setExecutablePath(path);
		}
		programManager.openProgram(program);
	}

	protected void setRegistersAndWaitForRecord(AbstractTestTargetRegisterBank<?> bank,
			Map<String, byte[]> values, long timeoutMillis) throws Exception {
		TraceThread traceThread = modelService.getTraceThread(bank.getThread());
		assertNotNull(traceThread);
		Trace trace = traceThread.getTrace();
		TraceRecorder recorder = modelService.getRecorder(trace);
		CompletableFuture<Void> observedTraceChange = new CompletableFuture<>();

		TraceDomainObjectListener listener = new TraceDomainObjectListener() {
			{
				listenFor(TraceMemoryBytesChangeType.CHANGED, this::bytesChanged);
			}

			void bytesChanged(TraceAddressSpace space, TraceAddressSnapRange range,
					byte[] oldValue, byte[] newValue) {
				if (space.getThread() != traceThread) {
					return;
				}
				TraceMemorySpace regSpace =
					trace.getMemoryManager().getMemoryRegisterSpace(traceThread, false);
				assertNotNull(regSpace);
				for (Map.Entry<String, byte[]> ent : values.entrySet()) {
					String regName = ent.getKey();
					Register register = trace.getBaseLanguage().getRegister(regName);
					RegisterValue recorded = regSpace.getValue(recorder.getSnap(), register);
					RegisterValue expected =
						new RegisterValue(register, new BigInteger(1, ent.getValue()));
					if (!recorded.equals(expected)) {
						continue;
					}
				}
				observedTraceChange.complete(null);
			}
		};
		try {
			trace.addListener(listener);
			// get() is not my favorite, but it'll do for testing
			// can't remove listener until observedTraceChange has completed.
			bank.writeRegistersNamed(values)
				.thenCompose(__ -> observedTraceChange)
				.get(timeoutMillis, TimeUnit.MILLISECONDS);
		}
		finally {
			trace.removeListener(listener);
		}
	}

	protected File pack(DomainObject object) throws Exception {
		File tempDir = Files.createTempDirectory("ghidra-" + name.getMethodName()).toFile();
		File pack = new File(tempDir, "obj" + System.identityHashCode(object) + ".gzf");
		object.saveToPackedFile(pack, monitor);
		return pack;
	}

	protected DomainFile unpack(File pack) throws Exception {
		return tool.getProject()
			.getProjectData()
			.getRootFolder()
			.createFile("Restored", pack, monitor);
	}
}
