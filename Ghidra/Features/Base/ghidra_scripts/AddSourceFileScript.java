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
// Adds a SourceFile with a user-defined path and name to the program.
//@category SourceMapping
import java.util.HexFormat;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.util.MessageType;

public class AddSourceFileScript extends GhidraScript {

	private static final String PATH = "Source File Path";
	private static final String ID_TYPE = "Id Type";
	private static final String IDENTIFIER = "Identifier";

	@Override
	protected void run() throws Exception {
		if (isRunningHeadless()) {
			println("This script must be run through the Ghidra GUI");
			return;
		}
		if (currentProgram == null) {
			popup("This script requires an open program");
			return;
		}
		if (!currentProgram.hasExclusiveAccess()) {
			popup("This script requires exclusive access to the program");
			return;
		}

		GhidraValuesMap values = new GhidraValuesMap();
		values.defineString(PATH, "/");
		SourceFileIdType[] idTypes = SourceFileIdType.values();
		String[] enumNames = new String[idTypes.length];
		for (int i = 0; i < enumNames.length; ++i) {
			enumNames[i] = idTypes[i].name();
		}
		values.defineChoice(ID_TYPE, SourceFileIdType.NONE.name(), enumNames);
		values.defineString(IDENTIFIER, StringUtils.EMPTY);

		values.setValidator((valueMap, status) -> {
			String path = valueMap.getString(PATH);
			SourceFileIdType idType = SourceFileIdType.valueOf(values.getChoice(ID_TYPE));
			byte[] identifier = null;
			if (idType != SourceFileIdType.NONE) {
				identifier = HexFormat.of().parseHex(values.getString(IDENTIFIER));
			}
			try {
				SourceFile srcFile = new SourceFile(path, idType, identifier);
				if (currentProgram.getSourceFileManager().containsSourceFile(srcFile)) {
					status.setStatusText("SourceFile " + srcFile + " already exists",
						MessageType.ERROR);
					return false;
				}
			}
			catch (IllegalArgumentException e) {
				status.setStatusText(e.getMessage(), MessageType.ERROR);
				return false;
			}
			return true;
		});
		askValues("Enter (Absolute) Source File URI Path",
			"e.g.: /usr/bin/echo, /C:/Programs/file.exe", values);
		String absolutePath = values.getString(PATH);
		SourceFileIdType idType = SourceFileIdType.valueOf(values.getChoice(ID_TYPE));
		byte[] identifier = null;
		if (idType != SourceFileIdType.NONE) {
			identifier = HexFormat.of().parseHex(values.getString(IDENTIFIER));
		}
		SourceFile srcFile = new SourceFile(absolutePath, idType, identifier);
		currentProgram.getSourceFileManager().addSourceFile(srcFile);
		printf("Successfully added source file %s%n", srcFile.toString());
	}

}
