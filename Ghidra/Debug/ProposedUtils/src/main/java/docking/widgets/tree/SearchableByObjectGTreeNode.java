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

import java.util.Map;

public interface SearchableByObjectGTreeNode {
	Map<? extends Object, ? extends GTreeNode> getObjectNodeMap();

	default GTreeNode findNodeForObject(Object obj) {
		Map<? extends Object, ? extends GTreeNode> index = getObjectNodeMap();
		synchronized (index) {
			GTreeNode node = index.get(obj);
			if (node != null) {
				return node;
			}
			for (GTreeNode sub : index.values()) {
				if (sub.isLeaf()) {
					continue;
				}
				if (!(sub instanceof SearchableByObjectGTreeNode)) {
					continue;
				}
				SearchableByObjectGTreeNode toSearch = (SearchableByObjectGTreeNode) sub;
				node = toSearch.findNodeForObject(obj);
				if (node != null) {
					return node;
				}
			}
			return null;
		}
	}
}
