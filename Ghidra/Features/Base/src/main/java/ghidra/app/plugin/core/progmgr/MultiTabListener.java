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
package ghidra.app.plugin.core.progmgr;

/**
 * 
 * Listener notified when tabs are added, removed, or selected 
 * in the MultiTabPanel.  
 * 
 * 
 */
public interface MultiTabListener {

	/**
	 * Notification that the given object is selected.
	 * @param obj object that is represented as a tab in the MultiTabPanel
	 */
	public void objectSelected(Object obj);
	
	
	/**
	 * Notification that the given object was added.
	 * @param obj object that is represented as a tab in the MultiTabPanel
	 */
	public void objectAdded(Object obj);
	
	/**
	 * Remove the object's tab if this method returns true.
	 * @param obj object that is represented as a tab in the MultiTabPanel
	 * @return true if the object's tab should be removed
	 */
	public boolean removeObject(Object obj);
	
}
