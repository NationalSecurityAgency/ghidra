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
package ghidra.feature.vt.gui.provider.functionassociation;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import docking.ActionContext;

public class VTFunctionAssociationContext extends ActionContext implements FunctionAssociationContext {

	private final PluginTool tool;
	private final Function selectedSourceFunction;
	private final Function selectedDestinationFunction;
	private final VTMatch existingMatch;

	/**
	 * Constructs a context for the function association provider.
	 * @param tool the tool containing the provider.
	 * @param selectedSourceFunction the source function currently selected in the table or null.
	 * @param selectedDestinationFunction the destination function currently selected in the table 
	 * or null.
	 * @param existingMatch the match for the indicated source and destination functions.
	 */
	public VTFunctionAssociationContext(PluginTool tool, Function selectedSourceFunction,
			Function selectedDestinationFunction, VTMatch existingMatch) {
		this.tool = tool;
		this.selectedSourceFunction = selectedSourceFunction;
		this.selectedDestinationFunction = selectedDestinationFunction;
		this.existingMatch = existingMatch;
	}

	@Override
	public Function getSelectedSourceFunction() {
		return selectedSourceFunction;
	}

	@Override
	public Function getSelectionDestinationFunction() {
		return selectedDestinationFunction;
	}

	@Override
	public VTMatch getExistingMatch() {
		return existingMatch;
	}

	@Override
	public boolean canCreateMatch() {
		if (selectedSourceFunction == null || selectedDestinationFunction == null) {
			return false;
		}

		return existingMatch == null; // can only create a match if one does not exist
	}

	/**
	 * @return the tool containing the function associations provider.
	 */
	public PluginTool getTool() {
		return tool;
	}
}
