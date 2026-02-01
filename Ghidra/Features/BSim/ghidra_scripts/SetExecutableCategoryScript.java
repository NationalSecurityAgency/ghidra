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
import org.apache.commons.lang3.StringUtils;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

//@category BSim
//sets a property on the current program which can be used as
//an executable category in BSim
public class SetExecutableCategoryScript extends GhidraScript {
	private static final String PROPERTY_NAME = "Property Name";
	private static final String PROPERTY_VALUE = "Property Value";

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			popup("This script requires a program");
			return;
		}
		GhidraValuesMap valuesMap = new GhidraValuesMap();
		valuesMap.defineString(PROPERTY_NAME);
		valuesMap.defineString(PROPERTY_VALUE);

		valuesMap.setValidator((values, status) -> {
			String name = valuesMap.getString(PROPERTY_NAME);
			if (StringUtils.isAllBlank(name)) {
				status.setStatusText("Name cannot be blank");
				return false;
			}
			String value = valuesMap.getString(PROPERTY_VALUE);
			if (StringUtils.isAllBlank(value)) {
				status.setStatusText("Value cannot be blank");
				return false;
			}
			return true;
		});

		askValues("Set Program Property", "Set Program Property", valuesMap);
		Options opts = currentProgram.getOptions(Program.PROGRAM_INFO);
		opts.setString(valuesMap.getString(PROPERTY_NAME), valuesMap.getString(PROPERTY_VALUE));
	}

}
