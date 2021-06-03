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
package docking.widgets.tree.internal;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import resources.ResourceManager;

public class InProgressGTreeRootNode extends GTreeNode {

	private static final Icon ICON = ResourceManager.loadImage("images/magnifier.png");

	@Override
	public String getName() {
		return "In Progress...";
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return ICON;
	}

	@Override
	public String getToolTip() {
		return "Please wait while building tree nodes.";
	}

	@Override
	public boolean isLeaf() {
		return true;
	}

}
