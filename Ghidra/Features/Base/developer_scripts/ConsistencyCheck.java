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
// Performs database consistency check on the current program
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import db.DBHandle;

public class ConsistencyCheck extends GhidraScript {

	@Override
	public void run() throws Exception {

		if (state.getTool() == null) {
			popup("Script requires active tool!");
			return;
		}

		ProgramManager programMgr = state.getTool().getService(ProgramManager.class);
		if (programMgr == null) {
			popup("Script requires Program Manager service!");
			return;
		}

		if (currentProgram == null) {
			popup("Script requires open/active program!");
			return;
		}

		DBHandle dbh = ((ProgramDB) currentProgram).getDBHandle();
		if (dbh.isChanged()) {
			popup("Current program must be saved prior to running!");
			return;
		}

		DomainFile df = currentProgram.getDomainFile();

		if (dbh.isConsistent(monitor)) {
			popup("Program database is consistent!");
			return;
		}

		if (!df.canSave() || !currentProgram.hasExclusiveAccess()) {
			popup("Program database is NOT consistent!\nRebuild requires exclusive checkout.");
			return;
		}

		if (!askYesNo("Rebuild Database?",
			"Program database is NOT consistent!\nWould you like to rebuild?")) {
			return;
		}

		end(false);
		programMgr.closeProgram(currentProgram, true);

		currentProgram = (Program) df.getDomainObject(this, false, false, monitor);
		dbh = ((ProgramDB) currentProgram).getDBHandle();

		try {
			boolean success = false;
			long txId = dbh.startTransaction();
			try {
				success = dbh.rebuild(monitor);
			}
			finally {
				dbh.endTransaction(txId, success);
			}

			if (!success) {
				popup("Rebuild Failed!");
				return;
			}

			if (!askYesNo("Save Database?",
				"Program database rebuilt successfully!\nWould you like to save?")) {
				return;
			}

			currentProgram.save("DB Rebuild", monitor);
		}
		finally {
			currentProgram.release(this);
			currentProgram = programMgr.openProgram(df);
			start();
		}
	}

}
