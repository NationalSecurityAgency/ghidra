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
package ghidra.app.cmd.refs;

import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Command for setting the external program name and path.
 */
public class SetExternalNameCmd implements Command<Program> {

	private String externalName;
	private String externalPath;
	private SourceType source;
	
	private String status;

	/**
	 * Constructs a new command for creating a Library, if it does not exist, and optionally 
	 * setting the associated external program path.  If created, a {@link SourceType#USER_DEFINED}
	 * source will be specified.
	 * @param externalName the Library name.
	 * @param externalPath the project file path of the program file to associate with the Library.
	 */
	public SetExternalNameCmd(String externalName, String externalPath) {
		this(externalName, externalPath, SourceType.USER_DEFINED);
	}
	
	/**
	 * Constructs a new command for creating a Library, if it does not exist, and optionally 
	 * setting the associated external program path.
	 * @param externalName the Library name.
	 * @param externalPath the project file path of the program file to associate with the Library.
	 * @param source the symbol source type to be applied if the library must be created.
	 */
	public SetExternalNameCmd(String externalName, String externalPath, SourceType source) {
		this.externalName = externalName;
		this.externalPath = externalPath;
		this.source = source;
	}

	@Override
	public boolean applyTo(Program program) {
		try {
			ExternalManager externalManager = program.getExternalManager();
			Library library = externalManager.getExternalLibrary(externalName);
			if (library == null) {
				externalManager.addExternalLibraryName(externalName, source);
			}
			library.setAssociatedProgramPath(externalPath);
		}
		catch (DuplicateNameException | InvalidInputException e) {
			status = e.getMessage();
		}
		return false;
	}

	@Override
	public String getStatusMsg() {
		return status;
	}

	@Override
	public String getName() {
		return "Set External Library Name and Path";
	}

}
