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

public interface EditorAction extends CompositeEditorModelListener {

	static final String BASIC_ACTION_GROUP = "1_BASIC_EDITOR_ACTION";
	static final String DATA_ACTION_GROUP = "2_DATA_EDITOR_ACTION";
	static final String COMPONENT_ACTION_GROUP = "3_COMPONENT_EDITOR_ACTION";
	static final String BITFIELD_ACTION_GROUP = "4_COMPONENT_EDITOR_ACTION";

	/**
	 * Method to set the action's enablement based on the associated editor
	 * model's current state.
	 */
	public void adjustEnablement();

}
