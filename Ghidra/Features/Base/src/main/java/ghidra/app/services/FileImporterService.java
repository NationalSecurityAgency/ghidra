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
package ghidra.app.services;

import java.io.File;
import java.util.List;

import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.ServiceInfo;

/**
 * Service for importing files into Ghidra.
 *
 */
@ServiceInfo(description = "Imports external files into program")
public interface FileImporterService {

	/**
	 * Imports the given file into the specified Ghidra project folder.
	 * @param folder the Ghidra project folder to store the imported file.
	 * @param file the file to import.
	 */
	public void importFile(DomainFolder folder, File file);

	/**
	 * Imports the given files into the specified Ghidra project folder.
	 * @param folder the Ghidra project folder to store the imported files.
	 * @param files the files to import.
	 */
	public void importFiles(DomainFolder folder, List<File> files);
}
