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
package docking;

import java.awt.Component;

/**
 * A listener interface to know when a component has been 
 * made {@link Component#isDisplayable() displayable}
 */
public interface ComponentLoadedListener {

	/**
	 * Called when the component is made displayable
	 * 
	 * @param windowManager the window manager associated with the loaded component; null if the
	 *        component for this listener is not parented by a docking window manager
	 * @param provider the provider that is the parent of the given component; null if the
	 *        component for this listener is not the child of a component provider
	 */
	public void componentLoaded(DockingWindowManager windowManager, ComponentProvider provider);
}
