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
package ghidra.app.merge.tool;

import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.JComponent;

import docking.*;
import docking.action.DockingActionIf;
import docking.actions.PopupActionProvider;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.framework.plugintool.*;

public class ListingMergePanelProvider extends ComponentProviderAdapter
		implements PopupActionProvider {
	private ListingMergePanel mergePanel;

	public ListingMergePanelProvider(PluginTool tool, Plugin plugin, String owner,
			ListingMergePanel mergePanel) {
		super(tool, "ListingMergePanel", owner);
		setTitle("Listing Merge Tool");
		setDefaultWindowPosition(WindowPosition.TOP);
		this.mergePanel = mergePanel;
		tool.addPopupActionProvider(this);
	}

	@Override
	public JComponent getComponent() {
		return mergePanel;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Object obj = mergePanel.getActionContext(event);
		return createContext(obj);
	}

	void dispose() {
		tool.removePopupActionProvider(this);
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool dt, ActionContext context) {
		ListingPanel resultPanel = mergePanel.getResultPanel();
		if (resultPanel != null) {
			return resultPanel.getHeaderActions(getName());
		}
		return null;
	}
}
