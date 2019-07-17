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
package docking.widgets.table;

/**
 * A listener that will get notified of selections made by the {@link SelectionManager}.
 */
public interface SelectionManagerListener {

	/**
	 * Called before and after a selection is restored.  This is useful for clients that wish to
	 * know when selections are changing due to the SelectionManager versus user initiated 
	 * selections or programmatic selections.
	 * @param preRestore true if the {@link SelectionManager} is about to restore selections; 
	 *                   false when the {@link SelectionManager} is finished restoring selections.
	 */
	public void restoringSelection(boolean preRestore);
}
