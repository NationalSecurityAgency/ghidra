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
package docking.widgets.tree.support;

import java.util.Set;

import docking.widgets.tree.GTreeNode;

/**
 * GTreeFilter that allows for some nodes that are never filtered out.
 */
public class IgnoredNodesGtreeFilter implements GTreeFilter {

	private GTreeFilter filter;
	private Set<GTreeNode> ignoredNodes;

	public IgnoredNodesGtreeFilter(GTreeFilter filter, Set<GTreeNode> ignoredNodes) {
		this.filter = filter;
		this.ignoredNodes = ignoredNodes;
	}

	@Override
	public boolean acceptsNode(GTreeNode node) {
		if (ignoredNodes.contains(node)) {
			return true;
		}
		return filter.acceptsNode(node);
	}

	@Override
	public boolean showFilterMatches() {
		return filter.showFilterMatches();
	}

}
