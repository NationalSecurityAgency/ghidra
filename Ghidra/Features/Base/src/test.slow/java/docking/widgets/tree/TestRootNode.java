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
package docking.widgets.tree;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

class TestRootNode extends GTreeNode {

	TestRootNode() {
		List<GTreeNode> children = new ArrayList<>();
		children.add(new LeafNode("XYZ"));
		children.add(new LeafNode("ABC"));
		children.add(new LeafNode("ABCX"));
		children.add(new LeafNode("XABC"));
		children.add(new LeafNode("XABCX"));
		setChildren(children);
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getName() {
		return "Root";
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
