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
package ghidra.app.plugin.core.compositeeditor;

import ghidra.program.model.data.*;

/**
 * <code>ComponentContext</code> provides a selected component context when editing a structure/union
  */
public interface ComponentContext {

	/**
	 * Get editor's data type manager
	 * @return editor's datatype manager
	 */
	DataTypeManager getDataTypeManager();

	/**
	 * Get the editor's selected component's parent composite (structure or union)
	 * @return editor's selected component's parent composite
	 */
	Composite getCompositeDataType();

	/**
	 * Get the editor's selected component
	 * @return editor's selected component
	 */
	DataTypeComponent getDataTypeComponent();

}
