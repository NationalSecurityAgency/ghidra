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
// Automatically creates a structure definition based on the references seen to the structure
//   To use this, place the cursor on a function parameter for example func(int *this),
//   (for a C++ this call function)
//   This script will automatically create a structure definition for the pointed at structure
//   and fill it out based on the references found by the decompiler.
//
//   If the parameter is already a structure pointer, any new references found will be added
//   to the structure, even if the structure must grow.
//
//   Eventually this WILL be put into a global type analyzer, but for now it is most useful.
//
//   This script assumes good flow, that switch stmts are good.
//
//   This script CAN be used in the decompiler by assigning a Binding a Keyboard key to it, then
//   placing the cursor on the variable in the decompiler that is a structure pointer (even if it
//   isn't one now, and then pressing the Quick key.
//
//@category Data Types
//@keybinding F6

import ghidra.app.plugin.core.decompile.actions.FillOutStructureCmd;
import ghidra.app.script.GhidraScript;

public class CreateStructure extends GhidraScript {

	@Override
	public void run() {
		FillOutStructureCmd fillCmd =
			new FillOutStructureCmd(currentProgram, currentLocation, state.getTool());
		fillCmd.applyTo(currentProgram, this.monitor);
	}
}
