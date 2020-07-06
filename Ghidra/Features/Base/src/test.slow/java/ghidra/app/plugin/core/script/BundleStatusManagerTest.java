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
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.*;

import docking.ComponentProvider;
import docking.action.DockingActionIf;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import generic.util.Path;
import ghidra.app.plugin.core.osgi.*;

public class BundleStatusManagerTest extends AbstractGhidraScriptMgrPluginTest {
	protected static String BUNDLE_PATH =
		translateSeperators("$GHIDRA_HOME/Features/Base/ghidra_scripts");
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

	protected static String translateSeperators(String path) {
		if (!File.separator.equals("/")) {
			return path.replace("/", File.separator);
		}
		return path;
	}

	void enableViaGUI(int viewRow) throws InterruptedException {
		testBundleHostListener.reset();
		runSwing(() -> {
			bundleStatusTable.setValueAt(true, viewRow, 0);
		});
		waitForSwing();
		// we wait for the last event, the activation of the bundle.
		testBundleHostListener.awaitActivation();
	}

	void disableViaGUI(int viewRow) throws InterruptedException {
		testBundleHostListener.reset();
		runSwing(() -> {
			bundleStatusTable.setValueAt(false, viewRow, 0);
		});
		waitForSwing();
		testBundleHostListener.awaitDisablement();
	}

	void cleanViaGUI(int viewRow) throws InterruptedException {
		BundleStatus status = bundleStatusTableModel.getRowObject(viewRow);
		bundleStatusTable.selectRow(viewRow);
		assertNotNull(status);
	
		status.setSummary("not clean");
		DockingActionIf cleanBundlesAction = getActionByName(bundleStatusProvider, "CleanBundles");
		runSwing(() -> {
			cleanBundlesAction.actionPerformed(null);
		});
		waitForSwing();
	
		int count = 0;
	
		// after cleaning, status is cleared.
		do {
			if (status.getSummary().isEmpty()) {
				break;
			}
			Thread.sleep(250);
		}
		while (++count < 8);
	
		assertTrue("Failure, clean took too long", count < 8);
	}

	/**
	 * Find the view row index in the BundleStatusTableModel of the status with the given bundle path, or
	 * -1 if it's not found. 
	 * 
	 * @param bundlePath bundle path to find
	 * @return view row index or -1 if not found
	 */
	protected int getBundleRow(String bundlePath) {
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
	DockingActionIf getActionByName(ComponentProvider componentProvider, String actionName) {
		Set<DockingActionIf> actionSet =
			(Set<DockingActionIf>) getInstanceField("actionSet", bundleStatusProvider);
		for (DockingActionIf action : actionSet) {
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		return null;
	}

	@Test
	public void testDisableEnableScriptDirectory() throws Exception {
		//
		// Tests that the user can disable then enable a script directory
		//
		int viewRow = getBundleRow(BUNDLE_PATH);

		assertTrue(viewRow != -1);

		runSwing(() -> {
			bundleStatusTable.selectRow(viewRow);
			bundleStatusTable.scrollToSelectedRow();
		});
		waitForSwing();

		BundleStatus status = bundleStatusTableModel.getRowObject(viewRow);

		// check that it is currently enabled, and our script exists
		ResourceFile scriptFile = Path.fromPathString(SCRIPT_PATH);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);

		// disable it
		disableViaGUI(viewRow);
		assertTrue(!status.isEnabled());
		assertScriptNotInTable(scriptFile);

		// re-enable it
		enableViaGUI(viewRow);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);
	}

	@Test
	public void testRunCleanRun() throws Exception {
		int viewRow = getBundleRow(BUNDLE_PATH);

		assertTrue(viewRow != -1);

		runSwing(() -> {
			bundleStatusTable.selectRow(viewRow);
			bundleStatusTable.scrollToSelectedRow();
		});
		waitForSwing();

		BundleStatus status = bundleStatusTableModel.getRowObject(viewRow);

		// check that it is currently enabled, and our script exists
		ResourceFile scriptFile = Path.fromPathString(SCRIPT_PATH);
		assertTrue(status.isEnabled());
		assertScriptInTable(scriptFile);

		// run
		env.getTool().showComponentProvider(provider, true);
		selectScript(SCRIPT_NAME);
		runScript(SCRIPT_NAME);
		env.getTool().showComponentProvider(bundleStatusProvider, true);

		// clean
		cleanViaGUI(viewRow);

		// run
		env.getTool().showComponentProvider(provider, true);
		selectScript(SCRIPT_NAME);
		runScript(SCRIPT_NAME);
		env.getTool().showComponentProvider(bundleStatusProvider, true);

	}

	/**
	 * A {@link BundleHostListener} to help serialize bundle operations. 
	 */
	protected class TestBundleHostListener implements BundleHostListener {
		CountDownLatch activationLatch = new CountDownLatch(1);
		CountDownLatch disablementLatch = new CountDownLatch(1);

		TestBundleHostListener() {
		}

		void reset() {
			activationLatch = new CountDownLatch(1);
			disablementLatch = new CountDownLatch(1);
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
