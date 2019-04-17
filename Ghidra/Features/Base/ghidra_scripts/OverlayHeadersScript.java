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
//Places header structure on overlay segments

import java.io.File;

import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.util.CodeUnitInsertionException;

public class OverlayHeadersScript extends GhidraScript implements Ingredient {

	@Override
	public void run() throws Exception {
		// Get our configuration info and save for other scripts to use
		IngredientDescription[] ingredients = getIngredientDescriptions();
		for (IngredientDescription ingredient : ingredients) {
			state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
				ingredient.getDefaultValue());
		}
		if (!state.displayParameterGatherer("Script Options")) {
			return;
		}

		// Get our parameters for use here
		String overlayName = (String) state.getEnvironmentVar("OverlayName");
		File dataTypeArchive = (File) state.getEnvironmentVar("OverlayHeaderArchive");
		String dataTypeName = (String) state.getEnvironmentVar("OverlayHeaderName"); // must include datatype category

		// Create our history logger
		Address histAddr = currentProgram.getMemory().getMinAddress();
		String tmpString = "\nScript: OverlayHeaders()\n";
		tmpString = tmpString + "   Add " + dataTypeName + " structure\n   from " +
			dataTypeArchive.toString();

		// Get the datatype that we want to place on the overlays
		FileDataTypeManager dataTypeFileManager = openDataTypeArchive(dataTypeArchive, true);
		DataType dataType = dataTypeFileManager.getDataType(dataTypeName);
		dataTypeFileManager.close();
		if (dataType == null) {
			println("Can't find data type " + dataTypeName + " in " + dataTypeArchive.toString());
			throw new Exception(
				"Can't find data type " + dataTypeName + "\n in " + dataTypeArchive.toString());
		}

		// Now iterate over overlays the lay down structure 
		AddressSetView searchSet = currentProgram.getMemory();
		AddressRangeIterator addressRanges = searchSet.getAddressRanges(true);
		monitor.initialize(searchSet.getNumAddresses());
		int progressCount = 0;
		while (addressRanges.hasNext() && !monitor.isCancelled()) {
			AddressRange range = addressRanges.next();
			Address startAddr = range.getMinAddress();
			String rangeName = startAddr.toString();
			if (rangeName.startsWith(overlayName)) {
				try {
					createData(startAddr, dataType);
				}
				catch (CodeUnitInsertionException ex) {
					println("Error creating data type: " + ex);
				}
			}
			progressCount += range.getLength();
			monitor.setProgress(progressCount);
		}
	}

	@Override
	public IngredientDescription[] getIngredientDescriptions() {
		IngredientDescription[] retVal = new IngredientDescription[] {
			new IngredientDescription("OverlayName", "Overlay Name", GatherParamPanel.STRING, "ov"),
			new IngredientDescription("OverlayHeaderArchive", "Overlay Header Archive",
				GatherParamPanel.FILE, ""),
			new IngredientDescription("OverlayHeaderName", "Overlay Header Name",
				GatherParamPanel.STRING, "/overlay_header") };
		return retVal;
	}

}
