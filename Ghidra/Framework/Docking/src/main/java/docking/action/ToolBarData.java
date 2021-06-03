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
package docking.action;

import javax.swing.Icon;

import docking.DockingUtils;
import generic.json.Json;
import ghidra.util.SystemUtilities;

public class ToolBarData {
	private static final String NO_SUBGROUP = Character.toString('\uffff');

	private Icon icon;
	private String toolBarGroup;
	private String toolBarSubGroup;
	private DockingAction ownerAction;

	ToolBarData(DockingAction ownerAction, Icon icon, String toolBarGroup, String toolBarSubGroup) {
		this.icon = DockingUtils.scaleIconAsNeeded(icon);
		this.toolBarGroup = toolBarGroup;
		this.ownerAction = ownerAction;
		this.toolBarSubGroup = (toolBarSubGroup == null) ? NO_SUBGROUP : toolBarSubGroup;
	}

	public ToolBarData(Icon icon) {
		this(null, icon, null, NO_SUBGROUP);
	}

	public ToolBarData(Icon icon, String toolBarGroup) {
		this(null, icon, toolBarGroup, NO_SUBGROUP);
	}

	public ToolBarData(Icon icon, String toolBarGroup, String toolBarSubGroup) {
		this(null, icon, toolBarGroup, toolBarSubGroup);
	}

	/**
	 * Returns the toolbar icon assigned to this toolbar data.
	 * @return the icon
	 */
	public Icon getIcon() {
		return icon;
	}

	/**
	 * Returns the group of this toolbar data.  Actions belonging to the same group will appear
	 * next to each other. 
	 * @return the group
	 */
	public String getToolBarGroup() {
		return toolBarGroup;
	}

	/**
	 * Returns the subgroup string.  This string is used to sort items within a 
	 * {@link #getToolBarGroup() toolbar group}.  This value is not required.  If not specified, 
	 * then the value will effectively place this item at the end of its specified group.
	 * @return the subgroup
	 */
	public String getToolBarSubGroup() {
		return toolBarSubGroup;
	}

	public void setIcon(Icon newIcon) {
		if (icon == newIcon) {
			return;
		}
		ToolBarData oldData = new ToolBarData(icon, toolBarGroup, toolBarSubGroup);
		icon = DockingUtils.scaleIconAsNeeded(newIcon);
		firePropertyChanged(oldData);
	}

	public void setToolBarGroup(String newGroup) {
		if (SystemUtilities.isEqual(toolBarGroup, newGroup)) {
			return;
		}
		ToolBarData oldData = new ToolBarData(icon, toolBarGroup, toolBarSubGroup);
		toolBarGroup = newGroup;
		firePropertyChanged(oldData);
	}

	public void setToolBarSubGroup(String newSubGroup) {
		if (SystemUtilities.isEqual(toolBarSubGroup, newSubGroup)) {
			return;
		}
		ToolBarData oldData = new ToolBarData(icon, toolBarGroup, toolBarSubGroup);
		toolBarSubGroup = (newSubGroup == null) ? NO_SUBGROUP : newSubGroup;
		firePropertyChanged(oldData);
	}

	private void firePropertyChanged(ToolBarData oldData) {
		if (ownerAction != null) {
			ownerAction.firePropertyChanged(DockingActionIf.TOOLBAR_DATA_PROPERTY, oldData, this);
		}
	}

	@Override
	public String toString() {
		return Json.toString(this, "icon", "toolBarGroup", "toolBarSubGroup");
	}
}
