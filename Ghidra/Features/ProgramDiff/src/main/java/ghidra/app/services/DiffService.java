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

import ghidra.app.plugin.core.diff.ProgramDiffPlugin;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.listing.Program;

/**
 * Provides a service interface into the Diff Plugin for displaying
 * program differences between the current Program and another program.
 *
 */
@ServiceInfo(defaultProvider = ProgramDiffPlugin.class, description = "Find differences between two Programs")
public interface DiffService {

	/**
	 * Launch the Diff dialog and display differences between the current program 
	 * and the otherProgram.
	 * @param otherProgram a domain file for the program to Diff the current program against.
	 * @return true if the second program is opened and successfully Diffed.
	 */	
	public boolean launchDiff(DomainFile otherProgram);
	
	/**
	 * Launch the Diff dialog and display differences between the current program 
	 * and the otherProgram.
	 * @param otherProgram the program to Diff the current program against.
	 * @return true if the second program is opened and successfully Diffed.
	 */	
	public boolean launchDiff(Program otherProgram);
	
	/**
	 * Determine if the Diff service is currently displaying a Diff.
	 */
	public boolean inProgress();

}
