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
package ghidra.framework.main.datatree;

import javax.swing.Icon;
import javax.swing.UIManager;

import docking.tool.ToolConstants;
import docking.widgets.tree.GTreeNode;

public class NoProjectNode extends GTreeNode {

	@Override
	public Icon getIcon(boolean expanded) {
		return UIManager.getIcon("Tree.closedIcon");
	}

	@Override
	public String getName() {
		return ToolConstants.NO_ACTIVE_PROJECT;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return false;
	}

}
