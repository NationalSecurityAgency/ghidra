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
package ghidra.app.plugin.core.script;

import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;

public class BundleStatusManagerTest extends AbstractGhidraScriptMgrPluginTest {
	protected static String BUNDLE_PATH = "$GHIDRA_HOME/Features/Base/ghidra_scripts";
	protected static String SCRIPT_NAME = "HelloWorldScript.java";
	protected static String SCRIPT_PATH =
		translateSeperators("$GHIDRA_HOME/Features/Base/ghidra_scripts/" + SCRIPT_NAME);

	protected BundleStatusComponentProvider bundleStatusProvider;
	protected GTable bundleStatusTable;
	protected BundleStatusTableModel bundleStatusTableModel;

	protected TestBundleHostListener testBundleHostListener;

	@Before
	public void setupBundleStatusTests() {
		DockingActionIf bundleStatusAction = getAction(plugin, "Script Directories");
		performAction(bundleStatusAction, false);
		waitForSwing();
		bundleStatusProvider = waitForComponentProvider(BundleStatusComponentProvider.class);
		bundleStatusTable = (GTable) getInstanceField("bundleStatusTable", bundleStatusProvider);
		bundleStatusTableModel = (BundleStatusTableModel) getInstanceField("bundleStatusTableModel",
			bundleStatusProvider);
		testBundleHostListener = new TestBundleHostListener();
		provider.getBundleHost().addListener(testBundleHostListener);
	}

	@After
	public void cleanupBundleStatusTests() {
		provider.getBundleHost().removeListener(testBundleHostListener);
	}

	@Test
	public void testDisableEnableScriptDirectory() throws Exception {
		//
		// Tests that the user can disable then enable a script directory
		//
		int viewRow = getBundleRow(BUNDLE_PATH);
		selectRow(viewRow);

		BundleStatus status = bundleStatusTableModel.getRowObject(viewRow);

		// check that it is currently enabled, and our script exists
		ResourceFile scriptFile = generic.util.Path.fromPathString(SCRIPT_PATH);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);

		disableViaGUI(viewRow);
		assertTrue(!status.isEnabled());
		assertScriptNotInTable(scriptFile);

		enableViaGUI(viewRow);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);
	}

	@Test
	public void testRunCleanRun() throws Exception {

		int viewRow = getBundleRow(BUNDLE_PATH);
		assertNotEquals(viewRow, -1);

		selectRows(viewRow);

		BundleStatus status = bundleStatusTableModel.getRowObject(viewRow);

		// check that it is currently enabled, and our script exists
		ResourceFile scriptFile = generic.util.Path.fromPathString(SCRIPT_PATH);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);

		selectAndRunScript(SCRIPT_NAME);

		cleanViaGUI(viewRow);

		runSelectedScript(SCRIPT_NAME);
	}

	@Test
	public void testAddRunCleanRemoveTwoBundles() throws Exception {
		final String TEST_SCRIPT_NAME = testName.getMethodName();

		//@formatter:off
		final String EXPECTED_OUTPUT = 
				TEST_SCRIPT_NAME+".java> Running...\n" + 
				TEST_SCRIPT_NAME+".java> Hello from pack2.Klass2\n" + 
				TEST_SCRIPT_NAME+".java> Finished!\n";
		//@formatter:on
		final File dir1 = new File(getTestDirectoryPath() + "/test_scripts1");
		final File dir2 = new File(getTestDirectoryPath() + "/test_scripts2");
		try {
			dir1.mkdirs();
			//@formatter:off
			Files.writeString(new File(dir1, TEST_SCRIPT_NAME+".java").toPath(),
				"//@importpackage pack2\n" + 
				"\n" + 
				"import pack1.Klass1;\n" + 
				"import ghidra.app.script.GhidraScript;\n" + 
				"public class "+TEST_SCRIPT_NAME+" extends GhidraScript {\n" + 
				"  @Override\n" + 
				"  protected void run() throws Exception {\n" + 
				"    new Klass1(this).hello();\n" + 
				"  }\n" + 
				"}\n" 
			);
			File pack1 = new File(dir1,"pack1");
			pack1.mkdirs();
			Files.writeString(new File(pack1, "Klass1.java").toPath(),
				"package pack1;\n" + 
				"\n" + 
				"import ghidra.app.script.GhidraScript;\n" + 
				"import pack2.Klass2;\n" + 
				"\n" + 
				"public class Klass1 {\n" + 
				"  GhidraScript script;\n" + 
				"  public Klass1(GhidraScript script) {\n" + 
				"    this.script = script;\n" + 
				"  }\n" + 
				"\n" + 
				"  public void hello() {\n" + 
				"    new Klass2(script).hello();\n" + 
				"  }\n" + 
				"}\n"
			);
			dir2.mkdirs();
			File pack2 = new File(dir2,"pack2");
			pack2.mkdirs();
			Files.writeString(new File(pack2, "Klass2.java").toPath(),
				"package pack2;\n" + 
				"\n" + 
				"import ghidra.app.script.GhidraScript;\n" + 
				"import pack2.Klass2;\n" + 
				"\n" + 
				"public class Klass2 {\n" + 
				"  GhidraScript script;\n" + 
				"  public Klass2(GhidraScript script) {\n" + 
				"    this.script = script;\n" + 
				"  }\n" + 
				"\n" + 
				"  public void hello() {\n" + 
				"    script.println(\"Hello from pack2.Klass2\");\n" + 
				"  }\n" + 
				"}\n"
			);
			//@formatter:on

			addBundlesViaGUI(dir1, dir2);

			String output = selectAndRunScript(TEST_SCRIPT_NAME + ".java");
			assertEquals(EXPECTED_OUTPUT, output);

			int row1 = getBundleRow(dir1);
			int row2 = getBundleRow(dir2);
			assertNotEquals(row1, -1);
			assertNotEquals(row2, -1);

			cleanViaGUI(row1, row2);

			removeViaGUI(row1, row2);

			row1 = getBundleRow(dir1);
			row2 = getBundleRow(dir2);
			assertEquals(row1, -1);
			assertEquals(row2, -1);
		}
		finally {
			delete(dir1.toPath());
			delete(dir2.toPath());
		}
	}

	private static String translateSeperators(String path) {
		if (!File.separator.equals("/")) {
			return path.replace("/", File.separator);
		}
		return path;
	}

	private void enableViaGUI(int viewRow) throws InterruptedException {
		testBundleHostListener.reset();
		runSwing(() -> {
			bundleStatusTable.setValueAt(true, viewRow, 0);
		});
		waitForSwing();
		// we wait for the last event, the activation of the bundle.
		testBundleHostListener.awaitActivation();
	}

	private void disableViaGUI(int viewRow) throws InterruptedException {
		testBundleHostListener.reset();
		runSwing(() -> {
			bundleStatusTable.setValueAt(false, viewRow, 0);
		});
		waitForSwing();
		testBundleHostListener.awaitDisablement();
	}

	private void selectRow(int viewRow) {
		assertNotEquals(viewRow, -1);
		runSwing(() -> {
			bundleStatusTable.selectRow(viewRow);
			bundleStatusTable.scrollToSelectedRow();
		});
		waitForSwing();
	}

	private List<BundleStatus> selectRows(int... viewRows) {
		List<BundleStatus> statuses = Arrays.stream(viewRows)
				.mapToObj(bundleStatusTableModel::getRowObject)
				.collect(Collectors.toList());
		for (BundleStatus status : statuses) {
			assertNotNull(status);
		}

		runSwing(() -> {
			bundleStatusTable.clearSelection();
			for (int viewRow : viewRows) {
				bundleStatusTable.addRowSelectionInterval(viewRow, viewRow);
			}
		});

		return statuses;
	}

	private void removeViaGUI(int... viewRows) throws InterruptedException {
		assertTrue("removeViaGUI called with no arguments", viewRows.length > 0);
		selectRows(viewRows);

		List<BundleStatus> statuses = bundleStatusTableModel.getModelData();
		int initialSize = statuses.size();

		DockingActionIf removeBundlesAction =
			getActionByName(bundleStatusProvider, "RemoveBundles");
		performAction(removeBundlesAction);
		waitForSwing();

		int count = 0;
		do {
			if (statuses.size() <= initialSize - viewRows.length) {
				break;
			}
			Thread.sleep(250);
		}
		while (++count < 8);
		assertTrue("Failure, clean took too long", count < 8);

	}

	private void cleanViaGUI(int... viewRows) throws InterruptedException {
		assertTrue("cleanViaGUI called with no arguments", viewRows.length > 0);

		List<BundleStatus> statuses = selectRows(viewRows);

		List<File> binaryDirs = statuses.stream().map((status) -> {
			status.setSummary("no summary"); // we use the summary later to test that the bundle's been cleaned
			GhidraSourceBundle bundle = (GhidraSourceBundle) provider.getBundleHost()
					.getExistingGhidraBundle(status.getFile());
			assertNotNull(bundle);
			File binaryDir = ((Path) getInstanceField("binaryDir", bundle)).toFile();
			assertTrue("Clean of bundle that doesn't exist", binaryDir.exists());
			return binaryDir;
		}).collect(Collectors.toList());

		DockingActionIf cleanBundlesAction = getActionByName(bundleStatusProvider, "CleanBundles");
		performAction(cleanBundlesAction);
		waitForSwing();

		// after cleaning, status is cleared, test for a clear status to know we're done cleaning.
		int count = 0;
		do {
			if (statuses.stream().allMatch(status -> status.getSummary().isEmpty())) {
				break;
			}
			Thread.sleep(250);
		}
		while (++count < 8);
		assertTrue("Failure, clean took too long", count < 8);
		for (File binaryDir : binaryDirs) {
			assertFalse("Clean of bundle didn't remove directory", binaryDir.exists());
		}
	}

	private int getBundleRow(File dir) {
		return getBundleRow(generic.util.Path.toPathString(new ResourceFile(dir)));
	}

	/**
	 * Find the view row index in the BundleStatusTableModel of the status with the given bundle path, or
	 * -1 if it's not found. 
	 * 
	 * @param bundlePath bundle path to find
	 * @return view row index or -1 if not found
	 */
	private int getBundleRow(String bundlePath) {
		AtomicInteger rowref = new AtomicInteger(-1);
		runSwing(() -> {
			for (int i = 0; i < bundleStatusTableModel.getRowCount(); i++) {
				BundleStatus status = bundleStatusTableModel.getRowObject(i);
				if (bundlePath.equals(status.getPathAsString())) {
					rowref.set(i);
					break;
				}
			}
		});
		return rowref.get();
	}

	@SuppressWarnings("unchecked")
	private DockingActionIf getActionByName(ComponentProvider componentProvider,
			String actionName) {
		Set<DockingActionIf> actionSet =
			(Set<DockingActionIf>) getInstanceField("actionSet", bundleStatusProvider);
		for (DockingActionIf action : actionSet) {
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	/**
	 * Add a list of bundles with the addBundles dialogue.
	 * 
	 * <p>All bundles should reside in a common directory.
	 * 
	 * @param bundleFiles the bundle files
	 * @throws Exception if waitForUpdateOnChooser fails
	 */
	private void addBundlesViaGUI(File... bundleFiles) throws Exception {
		assertTrue("addBundlesViaGUI called with no arguments", bundleFiles.length > 0);

		DockingActionIf addBundlesAction = getActionByName(bundleStatusProvider, "AddBundles");
		performAction(addBundlesAction, false);
		waitForSwing();

		List<File> files = List.of(bundleFiles);

		GhidraFileChooser chooser = waitForDialogComponent(GhidraFileChooser.class);
		assertNotNull(chooser);

		runSwing(() -> chooser.setCurrentDirectory(bundleFiles[0]));
		waitForUpdateOnChooser(chooser);

		runSwing(() -> {
			// there is no setFiles method of GhidraFileChooser
			Object selectedFiles = getInstanceField("selectedFiles", chooser);
			invokeInstanceMethod("setFiles", selectedFiles, new Class[] { List.class },
				new Object[] { files });
			Object validatedFiles = getInstanceField("validatedFiles", chooser);
			invokeInstanceMethod("setFiles", validatedFiles, new Class[] { List.class },
				new Object[] { files });
		});
		waitForUpdateOnChooser(chooser);
		testBundleHostListener.reset(bundleFiles.length);
		pressButtonByText(chooser, "OK");
		waitForSwing();
		testBundleHostListener.awaitActivation();
	}

	public String selectAndRunScript(String scriptName) throws Exception {
		env.getTool().showComponentProvider(provider, true);
		selectScript(scriptName);
		String output = runSelectedScript(scriptName);
		env.getTool().showComponentProvider(bundleStatusProvider, true);
		return output;
	}

	/**
	 * A {@link BundleHostListener} to help serialize bundle operations. 
	 */
	private class TestBundleHostListener implements BundleHostListener {
		CountDownLatch activationLatch;
		CountDownLatch disablementLatch;

		TestBundleHostListener() {
			reset();
		}

		void reset() {
			reset(1);
		}

		void reset(int count) {
			activationLatch = new CountDownLatch(count);
			disablementLatch = new CountDownLatch(count);
		}

		@Override
		public void bundleActivationChange(GhidraBundle bundle, boolean newActivation) {
			if (newActivation) {
				activationLatch.countDown();
			}
		}

		@Override
		public void bundleEnablementChange(GhidraBundle bundle, boolean newEnablement) {
			if (!newEnablement) {
				disablementLatch.countDown();
			}
		}

		void awaitActivation() throws InterruptedException {
			assertTrue(activationLatch.await(5000, TimeUnit.MILLISECONDS));
		}

		void awaitDisablement() throws InterruptedException {
			assertTrue(disablementLatch.await(5000, TimeUnit.MILLISECONDS));
		}

	}

}
