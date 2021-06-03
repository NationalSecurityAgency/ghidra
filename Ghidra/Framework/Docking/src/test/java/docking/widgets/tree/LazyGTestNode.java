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

/**
 * Class for testing {@link GTreeLazyNode}
 */
public class LazyGTestNode extends GTreeLazyNode {
	private String name;
	private int depth;

	LazyGTestNode(String name, int depth) {
		this.name = name;
		this.depth = depth;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Icon getIcon(boolean expanded) {
		return null;
	}

	@Override
	public String getToolTip() {
		return "tooltip: " + name;
	}

	@Override
	public boolean isLeaf() {
		return depth == 0;
	}

	@Override
	protected List<GTreeNode> generateChildren() {
		List<GTreeNode> list = new ArrayList<>();
		if (depth == 0) {
			return list;
		}

		for (int i = 0; i < 3; i++) {
			String childName = name + "_" + i;
			list.add(new LazyGTestNode(childName, depth - 1));
		}
		return list;
	}

}
