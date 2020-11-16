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
package ghidra.app.plugin.core.script;

import javax.swing.Icon;

import docking.widgets.tree.GTreeNode;
import resources.ResourceManager;

public class ScriptCategoryNode extends GTreeNode {

	private static Icon OPEN_FOLDER = ResourceManager.loadImage("images/openSmallFolder.png");
	private static Icon CLOSED_FOLDER = ResourceManager.loadImage("images/closedSmallFolder.png");

	private final String name;

	ScriptCategoryNode(String name) {
		this.name = name;

	}

	@Override
	public Icon getIcon(boolean expanded) {
		return expanded ? OPEN_FOLDER : CLOSED_FOLDER;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isLeaf() {
		return getChildCount() == 0;
	}

}
