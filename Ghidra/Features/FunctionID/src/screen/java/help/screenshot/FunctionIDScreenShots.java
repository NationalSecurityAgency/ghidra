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

import java.io.File;
import java.util.List;
import java.util.Set;

import org.junit.*;

import docking.DialogComponentProvider;
import ghidra.app.util.viewer.field.AddressFieldFactory;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.plugin.FidPlugin;

public class FunctionIDScreenShots extends GhidraScreenShotGenerator {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		loadPlugin(FidPlugin.class);
	}

	public FunctionIDScreenShots() {
		super();
	}

	@Override
	@After
	public void tearDown() throws Exception {

		closeAllWindows();
		super.tearDown();
	}

	@Test
	public void testChooseActiveFidDbs() {
		performAction("Choose Active FidDbs", "FidPlugin", false);
		captureDialog();
	}

	@Test
	public void testDetachAttachedFidDb() throws Exception {
		File dbFile = setupDbFile("Old_FID_DB.fidb");
		try {
			performAction("Detach attached FidDb", "FidPlugin", false);
			captureDialog();
		}
		finally {
			dbFile.delete();
		}
	}

	@Test
	public void testPopulateFidDbFromPrograms1() throws Exception {
		populateFidDbFromPrograms();
	}

	@Test
	public void testFidHashCurrentFunction() throws Exception {
		positionCursor(0x004015c4, AddressFieldFactory.FIELD_NAME);
		performAction("FidDbHash Function", "FidPlugin", false);
		captureDialog();
	}

	private void detachAddonFidDbs() {
		FidFileManager fidFileManager = FidFileManager.getInstance();
		List<FidFile> allKnownFidDbs = fidFileManager.getUserAddedFiles();
		for (FidFile fidFile : allKnownFidDbs) {
			fidFileManager.removeUserFile(fidFile);
		}
	}

	private File setupDbFile(String dbFilename) {
		detachAddonFidDbs();

		File dbFile = new File(System.getProperty("user.home"), dbFilename);
		if (dbFile.exists()) {
			dbFile.delete();
		}
		dbFile.deleteOnExit();

		//
		// Note: we cannot do this, as the fake file we are creating fails to load
		// 		 fidFileManager.addUserFidFile(dbFile);
		//
		// Instead, just reach in there and put the fake file in the jam

		FidFileManager fidFileManager = FidFileManager.getInstance();
		fidFileManager.getFidFiles(); // this triggers initializing
		FidFile fidFile = (FidFile) invokeConstructor(FidFile.class,
			new Class[] { FidFileManager.class, File.class, boolean.class },
			new Object[] { fidFileManager, dbFile, false });

		@SuppressWarnings("unchecked")
		Set<FidFile> fidFiles = (Set<FidFile>) getInstanceField("fidFiles", fidFileManager);
		fidFiles.add(fidFile);

		return dbFile;
	}

	private void populateFidDbFromPrograms() throws Exception {
		File dbFile = setupDbFile("New_FID_DB.fidb");
		performAction("Populate FidDb from programs", "FidPlugin", false);
		captureDialog();
		dbFile.delete();
		DialogComponentProvider dialog;
		while ((dialog = getDialog()) != null) {
			DialogComponentProvider finalDialog = dialog;
			runSwing(() -> finalDialog.close());
			Thread.sleep(100);
		}
	}
}
