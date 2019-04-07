/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.gui.plugin;

import ghidra.feature.vt.api.main.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

import java.util.Collection;
import java.util.List;

public class SubToolContext {

	private final VTPlugin plugin;
	private VTSubToolManager toolManager;

	private VTMatch match;

	public SubToolContext(VTPlugin plugin) {
		this.plugin = plugin;
		toolManager = plugin.getToolManager();
	}

	public Function getSourceFunction() {
		return toolManager.getSourceFunction();
	}

	public Function getDestinationFunction() {
		return toolManager.getDestinationFunction();
	}

	public boolean isSourceCursorOnScreen() {
		return toolManager.isSourceCursorOnScreen();
	}

	public boolean isDestinationCursorOnScreen() {
		return toolManager.isDestinationCursorOnScreen();
	}

	public VTMatch getMatch() {
		if (match == null) {
			match = getExistingMatch(getSourceFunction(), getDestinationFunction());
		}
		return match;
	}

	private VTMatch getExistingMatch(Function sourceFunction, Function destinationFunction) {
		if (sourceFunction == null || destinationFunction == null) {
			return null;
		}

		Address sourceAddress = sourceFunction.getEntryPoint();
		Address destinationAddress = destinationFunction.getEntryPoint();
		VTController controller = plugin.getController();
		VTSession session = controller.getSession();
		List<VTMatchSet> matchSets = session.getMatchSets();
		for (VTMatchSet matchSet : matchSets) {
			Collection<VTMatch> matches = matchSet.getMatches(sourceAddress, destinationAddress);
			for (VTMatch nextMatch : matches) {
				return nextMatch;
			}
		}
		return null;
	}
}
