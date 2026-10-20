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
package ghidra.app.util.sourcelanguage;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

import generic.jar.ResourceFile;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Rust data archives
 */
public class RustSourceLanguageDataArchive implements SourceLanguageDataArchive {

	@Override
	public SourceLanguageID getCompatibleSourceLanguage() {
		return RustSourceLanguage.RUST_ID;
	}

	@Override
	public List<DataArchiveRule> getDataArchiveRules(Program program, MessageLog log,
			TaskMonitor monitor) {
		final String filename = "types.json";
		try {
			ResourceFile dataArchiveConfileFile = Application.getModuleDataFile(filename);
			return DataArchiveUtils.readDataArchiveJsonConfig(dataArchiveConfileFile, program, log,
				monitor);
		}
		catch (FileNotFoundException e) {
			log.appendMsg("Failed to find module data file: " + filename);
		}
		catch (IOException e) {
			log.appendException(e);
		}
		return List.of();
	}
}
