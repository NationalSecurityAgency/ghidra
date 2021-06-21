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
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import javax.swing.*;
import javax.swing.tree.TreePath;

import org.junit.*;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.Unique;
import ghidra.app.plugin.core.debug.mapping.*;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceInternal;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServiceProxyPlugin;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.services.*;
import ghidra.dbg.model.AbstractTestTargetRegisterBank;
import ghidra.dbg.model.TestDebuggerModelBuilder;
import ghidra.dbg.target.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.model.*;
import ghidra.trace.model.Trace.TraceMemoryBytesChangeType;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.util.InvalidNameException;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.datastruct.ListenerMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;

public abstract class AbstractGhidraHeadedDebuggerGUITest
		extends AbstractGhidraHeadedIntegrationTest {

	protected static final String LANGID_TOYBE64 = "Toy:BE:64:default";

	public static class TestDebuggerTargetTraceMapper extends AbstractDebuggerTargetTraceMapper {
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
		MenuElement[] sel = MenuSelectionManager.defaultManager().getSelectedPath();
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
		MenuElement[] sel = MenuSelectionManager.defaultManager().getSelectedPath();
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
	protected ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

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
		if (tb != null) {
			if (traceManager != null && traceManager.getOpenTraces().contains(tb.trace)) {
				traceManager.closeTrace(tb.trace);
			}
			tb.close();
		}

		if (mb != null) {
			if (mb.testModel != null) {
				// TODO: Stop recordings, too?
				modelService.removeModel(mb.testModel);
			}
		}

		if (program != null) {
			programManager.closeAllPrograms(true);
			program.release(this);
		}

		env.dispose();
	}

	protected void createTestModel() throws Exception {
		mb.createTestModel();
		modelService.addModel(mb.testModel);
	}

	protected void nop() {
	}

	protected void intoProject(DomainObject obj)
			throws InvalidNameException, CancelledException, IOException {
		waitForDomainObject(obj);
		tool.getProject().getProjectData().getRootFolder().createFile(obj.getName(), obj, monitor);
	}

	protected void createSnaplessTrace() throws IOException {
		tb = new ToyDBTraceBuilder("dynamic-" + name.getMethodName(), LANGID_TOYBE64);
	}

	protected void addSnapshot(String desc) throws IOException {
		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.trace.getTimeManager().createSnapshot(desc);
		}
	}

	protected void createTrace() throws IOException {
		createSnaplessTrace();
		addSnapshot("First snap");
	}

	protected void createAndOpenTrace() throws IOException {
		createTrace();
		traceManager.openTrace(tb.trace);
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
		try (UndoableTransaction tid =
			UndoableTransaction.start(program, "Set Executable Path", true)) {
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
				TraceMemoryRegisterSpace regSpace =
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
