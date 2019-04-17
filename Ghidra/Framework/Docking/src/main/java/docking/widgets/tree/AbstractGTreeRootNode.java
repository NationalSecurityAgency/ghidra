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

/**
 * Simple base class for GTRootNodes.  If your root node has different internal logic
 * than other nodes, then extend this class.  If you root node has the same internal
 * logic as other nodes, then it is probably better to extend your other node class and
 * implement the getGTree() and setGTree() methods yourself.
 *
 */
public abstract class AbstractGTreeRootNode extends AbstractGTreeNode implements GTreeRootNode {
	private GTree tree;

	@Override
	public void setGTree(GTree tree) {
		this.tree = tree;
	}

	@Override
	public GTree getGTree() {
		return tree;
	}
}
