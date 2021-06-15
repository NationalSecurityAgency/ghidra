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
// Performs database consistency check on the current program
import db.DBHandle;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.ProgramDB;

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

		monitor.checkCanceled();

		if (!df.canSave() || !currentProgram.hasExclusiveAccess()) {
			popup("Program database is NOT consistent!\nRebuild requires exclusive checkout.");
			return;
		}

		if (!askYesNo("Rebuild Database?",
			"Program database is NOT consistent!\nWould you like to rebuild?")) {
			return;
		}

		end(false);

		ProgramDB program = (ProgramDB) df.getDomainObject(this, false, false, monitor);

		programMgr.closeProgram(currentProgram, true);

		monitor.clearCanceled(); // compensate for Script Manager cancelling task on program close

		dbh = program.getDBHandle();
		try {
			boolean success = false;
			int txId = program.startTransaction("Rebuild DB Indexes");
			try {
				success = dbh.rebuild(monitor);
			}
			finally {
				program.endTransaction(txId, success);
			}

			if (!success) {
				popup("Rebuild Failed!");
				return;
			}

			if (!askYesNo("Save Database?",
				"Program database rebuilt successfully!\nWould you like to save?")) {
				return;
			}

			program.save("DB Rebuild", monitor);
		}
		finally {
			programMgr.openProgram(program);
			program.release(this);
			currentProgram = program;
			start();
		}
	}

}
