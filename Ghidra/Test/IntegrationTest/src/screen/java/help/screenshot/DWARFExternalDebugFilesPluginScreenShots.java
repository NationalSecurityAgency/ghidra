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
import java.net.URI;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.external.*;
import ghidra.app.util.bin.format.dwarf.external.gui.ExternalDebugFilesConfigDialog;

public class DWARFExternalDebugFilesPluginScreenShots extends GhidraScreenShotGenerator {

	@Test
	public void testExternalDebugFilesConfigDialog() {
		LocalDirDebugInfoDProvider store = LocalDirDebugInfoDProvider.getGhidraCacheInstance();
		store = new LocalDirDebugInfoDProvider(store.getRootDir(), store.getName(),
			"Ghidra Cache Dir </var/tmp/user1-ghidra/debuginfo-cache>");

		LocalDirDebugInfoDProvider homeCache =
			LocalDirDebugInfoDProvider.getUserHomeCacheInstance();
		homeCache = new LocalDirDebugInfoDProvider(homeCache.getRootDir(), homeCache.getName(),
			"DebugInfoD Cache Dir </home/user1/.cache/debuginfod_client>");

		ExternalDebugFilesService edfs = new ExternalDebugFilesService(store, List.of());
		edfs.addProvider(new SameDirDebugInfoProvider(null));
		edfs.addProvider(homeCache);
		edfs.addProvider(new BuildIdDebugFileProvider(new File("/usr/lib/debug/.build-id")));
		edfs.addProvider(new HttpDebugInfoDProvider(URI.create("http://debuginfod.elfutils.org")));

		ExternalDebugFilesConfigDialog dlg = new ExternalDebugFilesConfigDialog();
		dlg.setService(edfs);
		showDialogWithoutBlocking(tool, dlg);
		waitForSwing();
		captureDialog(ExternalDebugFilesConfigDialog.class, 600, 300);
	}

}
