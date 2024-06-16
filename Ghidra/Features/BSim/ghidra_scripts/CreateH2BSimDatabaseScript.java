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
//Creates an empty file-based H2 BSim database
//@category BSim
import java.io.File;
import java.io.IOException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.BSimServerInfo.DBType;
import ghidra.features.bsim.query.FunctionDatabase.Error;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.*;
import ghidra.util.MessageType;
import ghidra.util.Msg;

public class CreateH2BSimDatabaseScript extends GhidraScript {
	private static final String NAME = "Database Name";
	private static final String DIRECTORY = "Database Directory";
	private static final String DATABASE_TEMPLATE = "Database Template";
	private static final String FUNCTION_TAGS = "Function Tags (CSV)";
	private static final String EXECUTABLE_CATEGORIES = "Executable Categories (CSV)";

	private static final String[] templates =
		{ "medium_nosize", "medium_32", "medium_64", "medium_cpool" };

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			popup("Use \"bsim\" to create an H2 BSim database from the command line");
			return;
		}

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(NAME, "");
		values.defineDirectory(DIRECTORY, new File(System.getProperty("user.home")));
		values.defineChoice(DATABASE_TEMPLATE, "medium_nosize", templates);
		values.defineString(FUNCTION_TAGS);
		values.defineString(EXECUTABLE_CATEGORIES);

		values.setValidator((valueMap, status) -> {
			String databaseName = valueMap.getString(NAME);
			if (StringUtils.isBlank(databaseName)) {
				status.setStatusText("Name must be filled in!", MessageType.ERROR);
				return false;
			}
			File directory = valueMap.getFile(DIRECTORY);
			if (!directory.isDirectory()) {
				status.setStatusText("Invalid directory!", MessageType.ERROR);
				return false;
			}
			File dbFile = new File(directory, databaseName);
			File testFile = new File(dbFile.getPath() + BSimServerInfo.H2_FILE_EXTENSION);
			if (testFile.exists()) {
				status.setStatusText("Database file already exists!", MessageType.ERROR);
				return false;
			}
			return true;
		});

		askValues("Enter Database Parameters",
			"Enter values required to create a new BSim H2 database.", values);

		FunctionDatabase h2Database = null;
		try {
			String databaseName = values.getString(NAME);
			File dbDir = values.getFile(DIRECTORY);
			String template = values.getChoice(DATABASE_TEMPLATE);
			String functionTagsCSV = values.getString(FUNCTION_TAGS);
			List<String> tags = parseCSV(functionTagsCSV);

			String exeCatCSV = values.getString(EXECUTABLE_CATEGORIES);
			List<String> cats = parseCSV(exeCatCSV);

			File dbFile = new File(dbDir, databaseName);

			BSimServerInfo serverInfo =
				new BSimServerInfo(DBType.file, null, 0, dbFile.getAbsolutePath());
			h2Database = BSimClientFactory.buildClient(serverInfo, false);
			BSimH2FileDataSource bds =
				BSimH2FileDBConnectionManager.getDataSourceIfExists(h2Database.getServerInfo());
			if (bds.getActiveConnections() > 0) {
				//if this happens, there is a connection to the database but the
				//database file was deleted
				Msg.showError(this, null, "Connection Error",
					"There is an existing connection to the database!");
				return;
			}

			CreateDatabase command = new CreateDatabase();
			command.info = new DatabaseInformation();
			// Put in fields provided on the command line
			// If they are null, the template will fill them in
			command.info.databasename = databaseName;
			command.config_template = template;
			command.info.trackcallgraph = true;
			ResponseInfo response = command.execute(h2Database);
			if (response == null) {
				throw new IOException(h2Database.getLastError().message);
			}

			for (String tag : tags) {
				InstallTagRequest req = new InstallTagRequest();
				req.tag_name = tag;
				ResponseInfo resp = req.execute(h2Database);
				if (resp == null) {
					Error lastError = h2Database.getLastError();
					throw new LSHException(lastError.message);
				}
			}

			for (String cat : cats) {
				InstallCategoryRequest req = new InstallCategoryRequest();
				req.type_name = cat;
				ResponseInfo resp = req.execute(h2Database);
				if (resp == null) {
					Error lastError = h2Database.getLastError();
					throw new LSHException(lastError.message);
				}
			}
			popup("Database " + values.getString(NAME) + " created successfully!");
		}
		finally {
			if (h2Database != null) {
				h2Database.close();
				BSimH2FileDataSource bds =
					BSimH2FileDBConnectionManager.getDataSourceIfExists(h2Database.getServerInfo());
				bds.dispose();
			}
		}

	}

	//this de-dupes
	private List<String> parseCSV(String csv) {
		Set<String> parsed = new HashSet<>();
		if (StringUtils.isEmpty(csv)) {
			return new ArrayList<String>();
		}
		String[] parts = csv.split(",");
		for (String p : parts) {
			if (!StringUtils.isBlank(p)) {
				parsed.add(p.trim());
			}
		}
		List<String> res = new ArrayList<>(parsed);
		res.sort(String::compareTo);
		return res;
	}

}
