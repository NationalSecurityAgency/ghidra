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
package ghidra.app.plugin.core.debug.gui.register;

import docking.widgets.table.DynamicTableColumn;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A factory for adding a custom column to the Registers table
 * 
 * <p>
 * All discovered factories' columns are automatically added as hidden columns to the Registers
 * table.
 */
public interface DebuggerRegisterColumnFactory extends ExtensionPoint {
	/**
	 * Create the column
	 * 
	 * @return the column
	 */
	DynamicTableColumn<RegisterRow, ?, ?> create();
}
