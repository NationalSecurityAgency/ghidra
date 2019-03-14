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
package docking.widgets.fieldpanel;

/**
 * A listener for field panel overlay events.
 * 
 * @see FieldPanelOverLayoutManager
 */
public interface FieldPanelOverLayoutListener {
	/**
	 * The manager is about to layout a component over a field in the panel
	 * @param ev the event describing the layout
	 */
	public void fieldLayout(FieldPanelOverLayoutEvent ev);
}
