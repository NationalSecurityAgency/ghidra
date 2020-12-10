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
package ghidra.app.plugin.core.debug.gui.target;

import javax.swing.tree.TreePath;

import docking.test.AbstractDockingTest;
import docking.widgets.tree.GTreeNode;
import docking.widgets.tree.support.GTreeSelectionEvent.EventOrigin;
import generic.test.AbstractGTest;

public interface DebuggerTargetsProviderFriend {
	static void selectNodeForObject(DebuggerTargetsProvider provider, Object target) {
		AbstractDockingTest.waitForTree(provider.tree);
		GTreeNode node = provider.rootNode.findNodeForObject(target);
		TreePath[] paths = new TreePath[] { node.getTreePath() };
		provider.tree.setSelectionPaths(paths, EventOrigin.USER_GENERATED);
		AbstractGTest.waitForCondition(() -> {
			TreePath path = provider.tree.getSelectionPath();
			return path != null && path.getLastPathComponent() == node;
		}, "Selection in target tree timed out");
	}
}
