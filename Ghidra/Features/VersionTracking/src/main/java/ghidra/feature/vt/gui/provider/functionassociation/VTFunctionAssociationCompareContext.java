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

import docking.ComponentProvider;
import ghidra.app.nav.Navigatable;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.duallisting.VTListingContext;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

/**
 * A context for the function association provider's code comparison panel that
 * will also allow function association table actions.
 */
public class VTFunctionAssociationCompareContext extends VTListingContext implements
		FunctionAssociationContext {

	private VTFunctionAssociationContext vtFunctionAssociationContext;

	/**
	 * Constructs a context for the function association provider's code comparison panel that
	 * will also allow function association table actions.
	 * @param provider the function association provider
	 * @param navigatable the dual listing navigatable.
	 * @param tool the tool containing the provider.
	 * @param selectedSourceFunction the source function currently selected in the table or null.
	 * @param selectedDestinationFunction the destination function currently selected in the table 
	 * or null.
	 * @param existingMatch the match for the indicated source and destination functions.
	 */
	public VTFunctionAssociationCompareContext(ComponentProvider provider, Navigatable navigatable,
			PluginTool tool, Function selectedSourceFunction,
			Function selectedDestinationFunction, VTMatch existingMatch) {

		super(provider, navigatable);
		vtFunctionAssociationContext =
			new VTFunctionAssociationContext(tool, selectedSourceFunction,
				selectedDestinationFunction,
			existingMatch);
	}

	@Override
	public Function getSelectedSourceFunction() {
		return vtFunctionAssociationContext.getSelectedSourceFunction();
	}

	@Override
	public Function getSelectionDestinationFunction() {
		return vtFunctionAssociationContext.getSelectionDestinationFunction();
	}

	@Override
	public VTMatch getExistingMatch() {
		return vtFunctionAssociationContext.getExistingMatch();
	}

	@Override
	public boolean canCreateMatch() {
		return vtFunctionAssociationContext.canCreateMatch();
	}
}
