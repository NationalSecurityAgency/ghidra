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
import ghidra.program.model.listing.Function;

/**
 * Action context interface for the function associations provider.
 */
public interface FunctionAssociationContext {

	/**
	 * Gets the source function selected in the table
	 * @return the selected source function or null
	 */
	public Function getSelectedSourceFunction();

	/**
	 * Gets the destination function selected in the table
	 * @return the selected destination function or null
	 */
	public Function getSelectionDestinationFunction();

	/**
	 * Gets the match for the source and destination functions if it exists.
	 * @return the match or null if there isn't a match.
	 */
	public VTMatch getExistingMatch();

	/**
	 * Determines if a function match can be created for the selected source and destination.
	 * @return true if the indicated match doesn't currently exist and can be created.
	 */
	public boolean canCreateMatch();

}
