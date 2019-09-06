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
package help.screenshot;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

import docking.DialogComponentProvider;
import generic.test.TestUtils;
import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.main.datatree.*;
import ghidra.framework.main.projectdata.actions.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.remote.User;
import ghidra.framework.store.*;
import ghidra.test.FrontEndTestEnv;
import ghidra.util.InvalidNameException;

public class VersionControlScreenShots extends GhidraScreenShotGenerator {

	@Override
	public void loadProgram() {
		// don't need to load a program
	}

	@Test
	public void testAddToVersionControlDialog() {
		VersionControlDialog dialog = new VersionControlDialog(true);
		dialog.setCurrentFileName("WinHelloCpp.exe");
		runSwing(() -> tool.showDialog(dialog), false);

		captureDialog();
	}

	@Test
	public void testCheckInFile() {

		VersionControlDialog dialog = new VersionControlDialog(false);
		dialog.setCurrentFileName(FrontEndTestEnv.PROGRAM_A);
		dialog.setKeepCheckboxEnabled(true);
		runSwing(() -> tool.showDialog(dialog), false);

		VersionControlDialog d = waitForDialogComponent(VersionControlDialog.class);
		captureDialog(d);
	}

	@Test
	public void testUndoHijack() {

		Plugin plugin = getFrontEndPlugin();
		VersionControlUndoHijackAction action = new VersionControlUndoHijackAction(plugin);
		DomainFile df = createDomainFile();
		List<DomainFile> hijackList = List.of(df);
		runSwing(() -> {

			TestUtils.invokeInstanceMethod("undoHijack", action, List.class, hijackList);

		}, false);

		UndoActionDialog d = waitForDialogComponent(UndoActionDialog.class);
		captureDialog(d);
	}

	@Test
	public void testUndoCheckoutDialog() {

		DomainFile df = createDomainFile();
		List<DomainFile> modifiedList = List.of(df);
		Plugin plugin = getFrontEndPlugin();
		VersionControlUndoCheckOutAction action = new VersionControlUndoCheckOutAction(plugin);
		runSwing(() -> {

			Class<?>[] paramTypes = new Class<?>[] { List.class, List.class };
			Object[] paramValues = new Object[] { Collections.emptyList(), modifiedList };
			TestUtils.invokeInstanceMethod("undoCheckOuts", action, paramTypes, paramValues);

		}, false);

		UndoActionDialog d = waitForDialogComponent(UndoActionDialog.class);
		captureDialog(d);
	}

	@Test
	public void testCheckOutFile() {

		User user = new User("User-1", 1);
		DomainFile df = createDomainFile();
		CheckoutDialog dialog = new CheckoutDialog(df, user);
		runSwing(() -> dialog.showDialog(), false);

		CheckoutDialog d = waitForDialogComponent(CheckoutDialog.class);
		captureDialog(d);
	}

	@Test
	public void testViewCheckouts() throws Exception {

		User user = new User("User-1", 0);
		DomainFile df = createDomainFile();

		//@formatter:off
		ItemCheckoutStatus[] checkouts = new ItemCheckoutStatus[] { 
			new ItemCheckoutStatus(1, CheckoutType.NORMAL, "User-1", 1, System.currentTimeMillis(), 
							       "host1::/path1/TestRepo"),
			new ItemCheckoutStatus(1, CheckoutType.EXCLUSIVE, "User-1", 1, System.currentTimeMillis(), 
				       "host1::/path2/TestRepo"), 
		};
		//@formatter:on
		CheckoutsDialog dialog = new CheckoutsDialog(tool, user, df, checkouts);
		tool.showDialog(dialog);

		DialogComponentProvider d =
			waitForDialogComponent("View Checkouts for " + FrontEndTestEnv.PROGRAM_A);

		captureDialog(d);
	}

	@Test
	public void testVersionHistory() throws Exception {

		DomainFile df = createDomainFile();
		VersionHistoryDialog dialog = new VersionHistoryDialog(df);
		runSwing(() -> tool.showDialog(dialog));

		VersionHistoryDialog d = waitForDialogComponent(dialog.getClass());
		captureDialog(d);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private DomainFile createDomainFile() {
		TestDummyDomainFolder root = new TestDummyDomainFolder(null, "Project");
		DomainFile df = new TestDummyDomainFile(root, "Program_A") {
			@Override
			public DomainFile setName(String newName) throws InvalidNameException, IOException {
				// stubbed to prevent exception from dummy
				return this;
			}

			@Override
			public Version[] getVersionHistory() throws IOException {
				long time = System.currentTimeMillis();
				String user = "User-1";
				//@formatter:off
				return new Version[] {
					new Version(1, time - 200000, user, "Comment 1"),
					new Version(2, time - 100000, user, "Comment 2"),
					new Version(3, time, user, "Comment 3"),
				};
				//@formatter:on
			}
		};
		return df;
	}

	private Plugin getFrontEndPlugin() {
		FrontEndTool feTool = env.showFrontEndTool();
		Plugin plugin = (Plugin) getInstanceField("plugin", feTool);
		return plugin;
	}
}
