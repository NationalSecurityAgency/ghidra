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
package ghidra.app.plugin.core.compositeeditor;

import ghidra.program.model.data.CategoryPath;

/**
 * Original Composite change listener interface.
 * This has a notification method for notification that the composite data 
 * editor has closed.
 */
interface OriginalCompositeListener {

	/**
	 * 
	 * @param newName the new name for the original data type being edited.
	 */
	void originalNameChanged(String newName);

	/**
	 * 
	 * @param newPath the new name for the original category where the 
	 * edited data type is to be applied.
	 */
	void originalCategoryChanged(CategoryPath newPath);

	/**
	 */
	void originalComponentsChanged();
}
