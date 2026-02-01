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
//Generates and commits the BSim signatures for the currentProgram to the
//selected H2 BSim database
//@category BSim
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Iterator;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class AddProgramToH2BSimDatabaseScript extends GhidraScript {

	private static final String DATABASE = "H2 Database";

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("Use the \"bsim\" command-line tool to add programs to a database headlessly");
			return;
		}

		if (currentProgram == null) {
			popup("This script requires that a program be open in the tool");
			return;
		}

		if (currentProgram.isChanged()) {
			popup(currentProgram.getName() + " has unsaved changes.  Please save the program" +
					" before adding it to a BSim database.");
			return;
		}

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineFile(DATABASE, null, new File(System.getProperty("user.home")));
		values.setValidator((valueMap, status) -> {
			File selected = valueMap.getFile(DATABASE);
			if (selected.isDirectory() ||
				!selected.getAbsolutePath().endsWith(BSimServerInfo.H2_FILE_EXTENSION)) {
				status.setStatusText("Invalid Database File!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		askValues("Select Database File", null, values);

		File h2DbFile = values.getFile(DATABASE);
		BSimServerInfo serverInfo = new BSimServerInfo(h2DbFile.getAbsolutePath());

		BSimH2FileDataSource existingBDS =
			BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
		if (existingBDS != null && existingBDS.getActiveConnections() > 0) {
			popup("There is an existing connection to the database.");
			return;
		}

		try (FunctionDatabase h2Database = BSimClientFactory.buildClient(serverInfo, false)) {

			h2Database.initialize();
			DatabaseInformation dbInfo = h2Database.getInfo();

			LSHVectorFactory vectorFactory = h2Database.getLSHVectorFactory();
			GenSignatures gensig = null;
			try {
				gensig = new GenSignatures(dbInfo.trackcallgraph);
				gensig.setVectorFactory(vectorFactory);
				gensig.addExecutableCategories(dbInfo.execats);
				gensig.addFunctionTags(dbInfo.functionTags);
				gensig.addDateColumnName(dbInfo.dateColumnName);

				DomainFile dFile = currentProgram.getDomainFile();
				URL fileURL = dFile.getSharedProjectURL(null);
				if (fileURL == null) {
					fileURL = dFile.getLocalProjectURL(null);
				}
				if (fileURL == null) {
					popup("Cannot add signatures for program which has never been saved");
					return;
				}

				String path = GhidraURL.getProjectPathname(fileURL);
				//bsim adds the program name to the path so we need to remove the program
				//name here
				int lastSlash = path.lastIndexOf('/');
				path = lastSlash == 0 ? "/" : path.substring(0, lastSlash);

				URL normalizedProjectURL = GhidraURL.getProjectURL(fileURL);
				String repo = normalizedProjectURL.toExternalForm();

				gensig.openProgram(this.currentProgram, null, null, null, repo, path);
				final FunctionManager fman = currentProgram.getFunctionManager();
				final Iterator<Function> iter = fman.getFunctions(true);
				gensig.scanFunctions(iter, fman.getFunctionCount(), monitor);
				final DescriptionManager manager = gensig.getDescriptionManager();
				if (manager.numFunctions() == 0) {
					Msg.showWarn(this, null, "Skipping Insert",
						currentProgram.getName() + " contains no functions with bodies");
					return;
				}

				//need to call sortCallGraph on each FunctionDescription
				//this de-dupes the list of callees for each function
				//without this there can be SQL errors due to inserting duplicate
				//entries into the callgraph table
				manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

				InsertRequest insertreq = new InsertRequest();
				insertreq.manage = manager;
				if (insertreq.execute(h2Database) == null) {
					BSimError lastError = h2Database.getLastError();
					if ((lastError.category == ErrorCategory.Format) ||
						(lastError.category == ErrorCategory.Nonfatal)) {
						Msg.showWarn(this, null, "Skipping Insert",
							currentProgram.getName() + ": " + lastError.message);
						return;
					}
					throw new IOException(currentProgram.getName() + ": " + lastError.message);
				}

				StringBuffer status = new StringBuffer(currentProgram.getName());
				status.append(" added to database ");
				status.append(dbInfo.databasename);
				status.append("\n\n");
				QueryExeCount exeCount = new QueryExeCount();
				ResponseExe countResponse = exeCount.execute(h2Database);
				if (countResponse != null) {
					status.append(dbInfo.databasename);
					status.append(" contains ");
					status.append(countResponse.recordCount);
					status.append(" executables.");
				}
				else {
					status.append("null response from QueryExeCount");
				}
				popup(status.toString());
			}
			finally {
				if (gensig != null) {
					gensig.dispose();
				}
			}

		}
		finally {
			if (existingBDS == null) {
				// Dispose database source if it did not previously exist
				BSimH2FileDataSource bds =
					BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
				if (bds != null) {
					bds.dispose();
				}
			}
		}
	}
}
