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
package ghidra.app.util.viewer.util;

import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;

/**
 * Action context for a CodeComparisonPanel.
 */
public interface CodeComparisonPanelActionContext {

	/**
	 * Gets the CodeComparisonPanel associated with this context.
	 * @return the code comparison panel.
	 */
	public abstract CodeComparisonPanel<? extends FieldPanelCoordinator> getCodeComparisonPanel();

}
