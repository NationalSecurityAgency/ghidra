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
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.junit.*;

import ghidra.app.util.bin.format.pdb.PdbInfo;
import ghidra.app.util.bin.format.pdb.PdbInfoDotNet;
import ghidra.app.util.datatype.microsoft.GUID;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import pdb.PdbPlugin;
import pdb.symbolserver.*;
import pdb.symbolserver.ui.ConfigPdbDialog;
import pdb.symbolserver.ui.LoadPdbDialog;

public class PdbScreenShots extends GhidraScreenShotGenerator {

	private static final String GUID1_STR = "012345670123012301230123456789AB";

	private int tx;
	private File temporaryDir;

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		temporaryDir = createTempDirectory("example_pdb");
		tx = program.startTransaction("set analyzed flag");
		Options proplist = program.getOptions(Program.PROGRAM_INFO);
		proplist.setBoolean(Program.ANALYZED, false);
		PdbInfo pdbInfo = PdbInfoDotNet.fromValues("HelloWorld.pdb", 1, new GUID(GUID1_STR));
		pdbInfo.serializeToOptions(proplist);
		proplist.setString("Executable Location",
			new File(temporaryDir, program.getName()).getPath());
	}

	@Override
	@After
	public void tearDown() throws Exception {
		program.endTransaction(tx, false);
		super.tearDown();
	}

	@Test
	public void testSymbolServerConfig_Screenshot() throws IOException {
		PdbPlugin.saveSymbolServerServiceConfig(null);
		ConfigPdbDialog configPdbDialog = new ConfigPdbDialog();
		showDialogWithoutBlocking(tool, configPdbDialog);
		waitForSwing();
		captureDialog(ConfigPdbDialog.class, 410, 280);
	}

	@Test
	public void testSymbolServerConfig_Configured() throws IOException {
		File localSymbolStore1Root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(localSymbolStore1Root, 1);
		LocalSymbolStore localSymbolStore1 = new LocalSymbolStore(localSymbolStore1Root);
		SameDirSymbolStore sameDirSymbolStore = new SameDirSymbolStore(null);
		List<SymbolServer> symbolServers = List.of(sameDirSymbolStore,
			new HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/")));
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, symbolServers);
		PdbPlugin.saveSymbolServerServiceConfig(symbolServerService);

		ConfigPdbDialog configPdbDialog = new ConfigPdbDialog();
		configPdbDialog.setSymbolServerService("/home/user/symbols", symbolServers);
		showDialogWithoutBlocking(tool, configPdbDialog);
		waitForSwing();
		captureDialog(ConfigPdbDialog.class, 410, 280);
	}

	@Test
	public void testLoadPdb_Initial_Screenshot() {
		LoadPdbDialog loadPdbDialog = new LoadPdbDialog(program);
		showDialogWithoutBlocking(tool, loadPdbDialog);
		captureDialog(loadPdbDialog);
		pressButtonByText(loadPdbDialog, "Cancel");
	}

	@Test
	public void testSymbolServerConfig_AddButtonMenu() throws IOException {
		File localSymbolStore1Root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(localSymbolStore1Root, 1);
		LocalSymbolStore localSymbolStore1 = new LocalSymbolStore(localSymbolStore1Root);
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, List.of());
		PdbPlugin.saveSymbolServerServiceConfig(symbolServerService);

		ConfigPdbDialog configPdbDialog = new ConfigPdbDialog();
		showDialogWithoutBlocking(tool, configPdbDialog);
		waitForSwing();
		runSwing(() -> {
			configPdbDialog.pushAddLocationButton();
		});
		waitForSwing();
		captureMenu();
	}

	@Test
	public void testLoadPdb_Advanced_NeedsConfig() {
		PdbPlugin.saveSymbolServerServiceConfig(null);
		LoadPdbDialog choosePdbDialog = new LoadPdbDialog(program);
		showDialogWithoutBlocking(tool, choosePdbDialog);
		waitForSwing();
		pressButtonByText(choosePdbDialog, "Advanced >>");
		waitForSwing();
		captureDialog(LoadPdbDialog.class, 600, 500);
		pressButtonByText(choosePdbDialog, "Cancel");
	}

	@Test
	public void testLoadPdb_Advanced_Screenshot() throws IOException {
		// Show the advanced side of the LoadPdbDialog, with
		// some faked search locations and search results so we
		// can have pretty paths
		File localSymbolStore1Root = new File(temporaryDir, "symbols");
		LocalSymbolStore.create(localSymbolStore1Root, 1);
		LocalSymbolStore localSymbolStore1 =
			new LocalSymbolStoreWithFakePath(localSymbolStore1Root, "/home/user/symbols");
		SameDirSymbolStoreWithFakePath sameDirSymbolStoreWithFakePath =
			new SameDirSymbolStoreWithFakePath(temporaryDir, "/home/user/examples");
		List<SymbolServer> symbolServers = List.of(sameDirSymbolStoreWithFakePath,
			new HttpSymbolServer(URI.create("https://msdl.microsoft.com/download/symbols/")));
		SymbolServerService symbolServerService =
			new SymbolServerService(localSymbolStore1, symbolServers);
		PdbPlugin.saveSymbolServerServiceConfig(symbolServerService);

		LoadPdbDialog loadPdbDialog = new LoadPdbDialog(program);
		showDialogWithoutBlocking(tool, loadPdbDialog);
		waitForSwing();
		pressButtonByText(loadPdbDialog, "Advanced >>");
		List<SymbolFileLocation> symbolFileLocations = List.of(
			new SymbolFileLocation("HelloWorld.pdb/" + GUID1_STR + "1/HelloWorld.pdb",
				localSymbolStore1, SymbolFileInfo.fromValues("HelloWorld.pdb", GUID1_STR, 1)),
			new SymbolFileLocation("HelloWorld.pdb/" + GUID1_STR + "2/HelloWorld.pdb",
				localSymbolStore1, SymbolFileInfo.fromValues("HelloWorld.pdb", GUID1_STR, 2)),
			new SymbolFileLocation("HelloWorld.pdb", sameDirSymbolStoreWithFakePath,
				SymbolFileInfo.fromValues("HelloWorld.pdb", GUID1_STR, 1)));
		Set<FindOption> findOptions = FindOption.of(FindOption.ALLOW_REMOTE, FindOption.ANY_AGE);
		runSwing(() -> {
			loadPdbDialog.setSearchOptions(findOptions);
			loadPdbDialog.setSearchResults(symbolFileLocations, findOptions);
			loadPdbDialog.selectRowByLocation(symbolFileLocations.get(0));
		});
		waitForSwing();
		captureDialog(LoadPdbDialog.class, 600, 600);
		pressButtonByText(loadPdbDialog, "Cancel");
	}

	private static class LocalSymbolStoreWithFakePath extends LocalSymbolStore {
		private String fakeRootDirPath;

		public LocalSymbolStoreWithFakePath(File rootDir, String fakeRootDirPath) {
			super(rootDir);
			this.fakeRootDirPath = fakeRootDirPath;
		}

		@Override
		public String getDescriptiveName() {
			return fakeRootDirPath;
		}

		@Override
		public String getFileLocation(String filename) {
			return FilenameUtils.concat(fakeRootDirPath, filename);
		}
	}

	private static class SameDirSymbolStoreWithFakePath extends SameDirSymbolStore {
		private String fakeRootDirPath;

		public SameDirSymbolStoreWithFakePath(File rootDir, String fakeRootDirPath) {
			super(rootDir);
			this.fakeRootDirPath = fakeRootDirPath;
		}

		@Override
		public String getDescriptiveName() {
			return String.format(PROGRAMS_IMPORT_LOCATION_DESCRIPTION_STR + " - %s",
				fakeRootDirPath);
		}

		@Override
		public String getFileLocation(String filename) {
			return FilenameUtils.concat(fakeRootDirPath, filename);
		}
	}
}
