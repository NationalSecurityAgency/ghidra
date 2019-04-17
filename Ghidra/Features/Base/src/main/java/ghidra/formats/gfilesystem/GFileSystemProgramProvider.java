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
package ghidra.formats.gfilesystem;

import ghidra.app.util.opinion.Loader;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GFileSystem} add-on interface that allows a filesystem publish the fact that
 * it supports an import feature allowing the caller to import binaries directly into
 * Ghidra without going through a {@link Loader}.
 */
public interface GFileSystemProgramProvider {

	/**
	 * NOTE: ONLY OVERRIDE THIS METHOD IF YOU CANNOT PROVIDE AN INPUT STREAM
	 * TO THE INTERNAL FILES OF THIS FILE SYSTEM!
	 * <br>
	 * BE SURE TO REGISTER THE GIVEN CONSUMER ON THE PROGRAM.
	 * <br>
	 * Returns a program for the given file.
	 * <br>
	 * @param file the file to convert into a program
	 * @param languageService the language service for locating languages and compiler specifications
	 * @param monitor a task monitor
	 * @param consumer the consumer for the program to be returned
	 * @return a program for the given file
	 * @throws Exception if errors occur
	 */

	public Program getProgram(GFile file, LanguageService languageService, TaskMonitor monitor,
			Object consumer) throws Exception;

	/**
	 * Returns true if this GFileSystem can convert the specified GFile instance into
	 * a Ghidra Program.
	 *
	 * @param file GFile file or directory instance.
	 * @return boolean true if calls to {@link #getProgram(GFile, LanguageService, TaskMonitor, Object)}
	 * will be able to convert the file into a program.
	 */
	public boolean canProvideProgram(GFile file);
}
