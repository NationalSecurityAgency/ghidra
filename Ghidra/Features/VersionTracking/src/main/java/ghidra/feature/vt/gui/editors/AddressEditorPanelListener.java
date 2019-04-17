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
package ghidra.feature.vt.gui.editors;

/**
 * The listener for an address editor panel. The listener gets notified of 
 * address edit changes when double click or <Enter> key actions occur.
 * The listener can then call the getAddress() on the editor panel for the current 
 * address value.
 */
public interface AddressEditorPanelListener {

	/**
	 * Notification that the address in the panel was edited.
	 * This gets called when double click or <Enter> key actions occur.
	 */
	void addressEdited();
}
