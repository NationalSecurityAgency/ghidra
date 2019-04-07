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

import java.util.Collections;
import java.util.List;

/**
 * Base class for GTNodes that want to use a lazy loading approach.  By using lazy
 * nodes, you don't have to create all the nodes up front and the nodes will only
 * be created as needed.  If you extend this base class, you have to implement one
 * additional method than if you extended AbstractGTreeNode and that is generateChildren().
 * The generateChildren() method will be called automatically when needed.
 */

public abstract class GTreeLazyNode extends AbstractGTreeNode {
	protected abstract List<GTreeNode> generateChildren();

	@Override
	protected final void loadChildren() {
		if (isChildrenLoadedOrInProgress()) {
			return;
		}
		List<GTreeNode> generateChildren = generateChildren();
		if (isChildrenLoadedOrInProgress()) {
			return;
		}
		doSetChildren(generateChildren, false);
	}

	@Override
	public void addNode(int index, GTreeNode node) {
		if (!isChildrenLoadedOrInProgress()) {
			return;
		}
		super.addNode(index, node);
	}

	/**
	 * A convenience method to return this node's children if they are loaded; an empty list
	 * if they are not loaded.  This allows clients that don't care either way to use the 
	 * list returned here without checking for null.
	 * 
	 * @return the loaded children 
	 */
	public List<GTreeNode> getAllChildrenIfLoaded() {
		if (isChildrenLoadedOrInProgress()) {
			return getAllChildren();
		}

		// not loaded; do not load
		return Collections.emptyList();
	}
}
