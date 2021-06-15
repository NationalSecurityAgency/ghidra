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
package ghidra.app.plugin.core.functiongraph;

import java.awt.Color;
import java.util.List;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphVertexAttributes;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;

class ToolBasedColorProvider implements FGColorProvider {

	private final ColorizingService service;
	private final FunctionGraphPlugin plugin;

	ToolBasedColorProvider(FunctionGraphPlugin plugin, ColorizingService colorizingService) {
		this.plugin = plugin;
		this.service = colorizingService;
	}

	@Override
	public boolean isUsingCustomColors() {
		return false;
	}

	@Override
	public void setVertexColor(FGVertex vertex, Color color) {
		Program program = plugin.getCurrentProgram();
		int id = program.startTransaction("Set Background Color");
		try {
			service.setBackgroundColor(vertex.getAddresses(), color);
		}
		finally {
			program.endTransaction(id, true);
		}

		vertex.setBackgroundColor(color);
	}

	@Override
	public void clearVertexColor(FGVertex vertex) {
		Program program = plugin.getCurrentProgram();
		int id = program.startTransaction("Set Background Color");
		try {
			service.clearBackgroundColor(vertex.getAddresses());
		}
		finally {
			program.endTransaction(id, true);
		}

		vertex.clearColor();
	}

	@Override
	public Color getColorFromUser(Color startColor) {
		return service.getColorFromUser(startColor);
	}

	@Override
	public Color getMostRecentColor() {
		return service.getMostRecentColor();
	}

	@Override
	public List<Color> getRecentColors() {
		return service.getRecentColors();
	}

	@Override
	public void savePluginColors(SaveState saveState) {
		// no-op; the loading/saving of colors is handled automatically by the service
	}

	@Override
	public void loadPluginColor(SaveState saveState) {
		// no-op; the loading/saving of colors is handled automatically by the service
	}

	@Override
	public void saveVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		// no-op; the loading/saving of colors is handled automatically by the service
	}

	@Override
	public void loadVertexColors(FGVertex vertex, FunctionGraphVertexAttributes settings) {
		// The loading/saving of colors is handled automatically by the service, but this is
		// for the background of the code units stored in the DB.  We still have to let this
		// vertex know that it has a custom background.

		AddressSetView addresses = vertex.getAddresses();
		AddressSetView allColorAddress = service.getAllBackgroundColorAddresses();
		if (!allColorAddress.contains(addresses)) {
			// sparse colors for the addresses of this node; assume this has not been colored 
			// from the function graph, but from the service for individual addresses.
			return;
		}

		Color savedColor = service.getBackgroundColor(vertex.getVertexAddress());
		if (savedColor != null) {
			vertex.restoreColor(savedColor);
		}
	}

}
