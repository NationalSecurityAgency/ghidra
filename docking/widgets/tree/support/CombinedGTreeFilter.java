/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import docking.widgets.tree.GTreeNode;

public class CombinedGTreeFilter implements GTreeFilter {

	private final GTreeFilter filter1;
	private final GTreeFilter filter2;

	public CombinedGTreeFilter(GTreeFilter filter1, GTreeFilter filter2) {
		this.filter1 = filter1;
		this.filter2 = filter2;
	}

	@Override
	public boolean acceptsNode(GTreeNode node) {
		return filter1.acceptsNode(node) && filter2.acceptsNode(node);
	}

	@Override
	public boolean showFilterMatches() {
		return filter1.showFilterMatches() && filter2.showFilterMatches();
	}

}
