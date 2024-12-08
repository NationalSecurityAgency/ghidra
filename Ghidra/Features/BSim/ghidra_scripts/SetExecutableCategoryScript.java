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
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

//@category BSim
//sets a property on the current program which can be used as
//an executable category in BSim
public class SetExecutableCategoryScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			popup("This script requires a program");
			return;
		}
		Options opts = currentProgram.getOptions(Program.PROGRAM_INFO);
		String name = askString("Enter Property Name", "Name");
		if (StringUtils.isAllBlank(name)) {
			return;
		}
		String value = askString("Enter Value of Property " + name, "Value");
		if (StringUtils.isAllBlank(value)) {
			return;
		}
		opts.setString(name, value);
	}

}
