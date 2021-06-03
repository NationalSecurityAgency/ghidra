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
package ghidra.framework.main.projectdata.actions;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.collections4.IterableUtils;
import org.junit.Before;
import org.junit.Test;

import docking.DialogComponentProvider;
import docking.test.AbstractDockingTest;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.DummyPluginTool;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

public class VersionControlCheckOutActionTest extends AbstractDockingTest {

	private SpyErrorLogger spyLogger = new SpyErrorLogger();
	private SpyErrorDisplay spyDisplay = new SpyErrorDisplay();

	private TestRootDomainFolder root;
	private Set<DomainFile> unversioned = new HashSet<>();
	private Set<DomainFile> notCheckedOut = new HashSet<>();
	private Set<DomainFile> failToCheckout = new HashSet<>();
	private Set<DomainFile> checkedOut = new HashSet<>();

	@Before
	public void setUp() throws Exception {

		// signal to use the error display
		System.setProperty(SystemUtilities.HEADLESS_PROPERTY, Boolean.FALSE.toString());

		root = new TestRootDomainFolder();
		createDomainFiles();

		Msg.setErrorLogger(spyLogger);
		Msg.setErrorDisplay(spyDisplay);
	}

	@Test
	public void testCheckOut_OnlyUnversionedFiles() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		checkout(action, unversioned);
		waitForTasks();

		assertNoLoggedMessages();
		spyDisplay.assertDisplayMessage("No", "versioned", "files");
	}

	@Test
	public void testCheckOut_OnlyVersionedAndNotCheckedOutFiles_ConfirmCheckout() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		checkout(action, notCheckedOut);
		confirmCheckout();
		waitForTasks();

		spyLogger.assertLogMessage("Checkout", "completed", Integer.toString(notCheckedOut.size()));
		assertNoDisplayedMessages();
	}

	@Test
	public void testCheckOut_OnlyVersionedAndNotCheckedOutFiles_CancelCheckout() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		checkout(action, notCheckedOut);
		cancelCheckout();
		waitForTasks();

		assertNoLoggedMessages();
		assertNoDisplayedMessages();
	}

	@Test
	public void testCheckOut_OnlyVersionedAndCheckedOutFiles() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		checkout(action, checkedOut);
		waitForTasks();

		assertNoLoggedMessages();
		spyDisplay.assertDisplayMessage("No", "versioned", "files");
	}

	@Test
	public void testCheckOut_OnlyVersionedFilesThatFailCheckout() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		checkout(action, failToCheckout);
		confirmCheckout();
		waitForTasks();

		// this only happens when not using spies
		// spyLogger.assertLogMessage("Multiple", "checkouts", "failed");
		spyDisplay.assertDisplayMessage("Multiple", "checkouts", "failed");
	}

	@Test
	public void testCheckOut_MixOfVersionedFilesThatDoAndDontFailCheckout() {

		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		Set<DomainFile> mixed = new HashSet<>();
		mixed.add(CollectionUtils.any(notCheckedOut));
		mixed.add(CollectionUtils.any(failToCheckout));
		checkout(action, mixed);
		confirmCheckout();
		waitForTasks();

		// this only happens when not using spies
		// spyLogger.assertLogMessage("Exclusive", "checkout", "failed");
		spyDisplay.assertDisplayMessage("Exclusive", "checkout", "failed");
	}

	@Test
	public void testCheckOut_SingleVersionedAndNotCheckedOutFile() {
		DummyPluginTool tool = new DummyPluginTool();
		VersionControlCheckOutAction action = new VersionControlCheckOutAction("owner", tool);

		spyLogger.reset();
		spyDisplay.reset();

		Set<DomainFile> file = new HashSet<>();
		file.add(CollectionUtils.any(notCheckedOut));
		checkout(action, file);
		waitForTasks();

		spyLogger.assertLogMessage("Checkout", "completed", "1");
		assertNoDisplayedMessages();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void checkout(VersionControlCheckOutAction action, Set<DomainFile> files) {
		runSwing(() -> action.checkOut(files), false);
	}

	private void confirmCheckout() {
		DialogComponentProvider dialog = waitForDialogComponent("Confirm Bulk Checkout");
		pressButtonByText(dialog, "Yes");
	}

	private void cancelCheckout() {
		DialogComponentProvider dialog = waitForDialogComponent("Confirm Bulk Checkout");
		pressButtonByText(dialog, "No");
	}

	private void assertNoLoggedMessages() {
		assertTrue("Spy logger not empty: " + spyLogger, IterableUtils.isEmpty(spyLogger));
	}

	private void assertNoDisplayedMessages() {
		assertTrue("Spy display not empty: " + spyDisplay, IterableUtils.isEmpty(spyDisplay));
	}

	private void createDomainFiles() throws Exception {

		int ordinal = 1;
		int end = ordinal + 3;
		for (; ordinal < end; ordinal++) {
			TestDummyDomainFile testFile =
				(TestDummyDomainFile) root.createFile("Program_" + ordinal, (DomainObject) null,
					null);
			unversioned.add(testFile);
		}

		end = ordinal + 3;
		for (; ordinal < end; ordinal++) {
			TestDummyDomainFile testFile =
				(TestDummyDomainFile) root.createFile("Program_" + ordinal, (DomainObject) null,
					null);

			// versioned, but not checked out
			testFile.setVersioned();
			notCheckedOut.add(testFile);
		}

		end = ordinal + 3;
		for (; ordinal < end; ordinal++) {
			CheckoutableDomainFile testFile =
				(CheckoutableDomainFile) root.createFile("Program_" + ordinal, (DomainObject) null,
					null);

			// versioned, but not checked out; cannot checkout
			testFile.setVersioned();
			testFile.setUnableToCheckout();
			failToCheckout.add(testFile);
		}

		end = ordinal + 3;
		for (; ordinal < end; ordinal++) {
			TestDummyDomainFile testFile =
				(TestDummyDomainFile) root.createFile("Program_" + ordinal, (DomainObject) null,
					null);

			// versioned and checked out
			testFile.setVersioned();
			testFile.setCheckedOut();
			checkedOut.add(testFile);
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class TestRootDomainFolder extends TestDummyDomainFolder {

		public TestRootDomainFolder() {
			super(null, "Root");
		}

		@Override
		public synchronized DomainFile createFile(String name, DomainObject obj,
				TaskMonitor monitor) throws InvalidNameException, IOException, CancelledException {

			DomainFile file = new CheckoutableDomainFile(this, name);
			files.add(file);
			return file;
		}

	}

	private class CheckoutableDomainFile extends TestDummyDomainFile {

		private boolean ableToCheckout = true;

		public CheckoutableDomainFile(TestDummyDomainFolder parent, String name) {
			super(parent, name);
		}

		void setUnableToCheckout() {
			ableToCheckout = false;
		}

		@Override
		public boolean checkout(boolean exclusive, TaskMonitor monitor)
				throws IOException, CancelledException {

			return ableToCheckout;
		}
	}
}
