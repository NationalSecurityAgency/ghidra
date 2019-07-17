/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.app.script.GhidraScript;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitorAdapter;

import java.io.File;
import java.io.IOException;

import db.DBConstants;
import db.DBHandle;

public class UpgradeTestProgramScript extends GhidraScript {

	@Override
	public void run() throws Exception {

//		File testResourceDirectory = RunInfo.getCoreSubDirectory("test_resources");
//		
//		File gzf = this.askFile("Upgrade Program Archive", testResourceDirectory, "Upgrade");
//		if (!gzf.getName().endsWith(".gzf")) {
//			popup("Only Ghidra Zip files (*.gzf) are supported!");
//			return;
//		}
//
//		if (upgradeProgramArchive(gzf)) {
//			popup("Program upgraded");
//		}

		File gzfDir = this.askDirectory("Upgrade Program Archives", "Upgrade All");

		if (!askYesNo("Upgrade Program Archives",
			"Do you want to upgrade all Program archives in the directory: " + gzfDir.getName() +
				"?")) {
			return;
		}

		upgradeDir(gzfDir);

	}

	private void upgradeDir(File dir) throws CancelledException, VersionException, IOException {

		if ("upgrades".equals(dir.getName())) {
			return; // ignore the special upgrade directory
		}

		for (File f : dir.listFiles()) {
			if (f.isFile() && f.getName().endsWith(".gzf")) {
				Msg.info(this, "Processing " + f.getName() + " ...");
				if (upgradeProgramArchive(f)) {
					Msg.info(this, "   program upgraded!");
				}
			}
			else if (f.isDirectory()) {
				upgradeDir(f);
			}
		}
	}

	private boolean upgradeProgramArchive(File gzf) throws IOException, CancelledException,
			VersionException {

		PackedDatabase db = PackedDatabase.getPackedDatabase(gzf, TaskMonitorAdapter.DUMMY_MONITOR);
		DBHandle dbh = null;
		ProgramDB p = null;
		try {
			dbh = db.openForUpdate(monitor);

			if (dbh.getTable("Program") == null) {
				return false;
			}

			try {
				p = new ProgramDB(dbh, DBConstants.UPDATE, monitor, this);
				return false;
			}
			catch (LanguageNotFoundException e) {
				Msg.error(this, e.getMessage());
				return false;
			}
			catch (VersionException e) {
				if (!e.isUpgradable()) {
					Msg.error(this, e.getMessage());
					return false;
				}
			}
			finally {
				dbh.close();
			}

			dbh = db.openForUpdate(monitor);
			p = new ProgramDB(dbh, DBConstants.UPGRADE, monitor, this);

			if (!p.isChanged()) {
				return false;
			}

			p.save(null, monitor);
		}
		finally {
			if (p != null) {
				p.release(this);
			}
			if (dbh != null) {
				dbh.close();
			}
			db.dispose();
		}

		return true;
	}

}
