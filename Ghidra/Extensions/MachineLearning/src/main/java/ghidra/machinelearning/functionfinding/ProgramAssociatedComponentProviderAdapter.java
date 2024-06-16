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
package ghidra.machinelearning.functionfinding;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;

/**
 * This class is used by {@link RandomForestFunctionFinderPlugin}, which can create various
 * components for displaying potential function starts in a given program (and related info).
 * The purpose of this class is to facilitate closing all components associated with a program
 * when that program is closed.
 */
public abstract class ProgramAssociatedComponentProviderAdapter extends ComponentProviderAdapter {

	private Program program;
	private RandomForestFunctionFinderPlugin plugin;

	/**
	 * Creates a {@link ComponentProviderAdapter} with an associated {@link Program} and {
	 * {@link RandomForestFunctionFinderPlugin}
	 * @param name name 
	 * @param owner owner
	 * @param program associated program
	 * @param plugin plugin
	 */
	public ProgramAssociatedComponentProviderAdapter(String name, String owner, Program program,
			RandomForestFunctionFinderPlugin plugin) {
		super(plugin.getTool(), name, owner);
		this.program = program;
		this.plugin = plugin;
		setTransient();
		setWindowMenuGroup("Search for Code and Functions");
	}

	/**
	 * Returns the associated program
	 * @return the program
	 */
	Program getProgram() {
		return program;
	}

	@Override
	public void closeComponent() {
		plugin.removeProvider(this);
		super.closeComponent();
	}

}
