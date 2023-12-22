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

import java.util.List;
import java.util.stream.Stream;

import docking.widgets.filter.MultitermEvaluationMode;
import docking.widgets.filter.TextFilter;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.FilterTransformer;

public class MultiTextFilterTreeFilter implements GTreeFilter {

	private final List<TextFilter> filters;
	private final FilterTransformer<GTreeNode> transformer;
	private final MultitermEvaluationMode evalMode;

	public MultiTextFilterTreeFilter(List<TextFilter> filters,
			FilterTransformer<GTreeNode> transformer, MultitermEvaluationMode evalMode) {
		this.filters = filters;
		this.transformer = transformer;
		this.evalMode = evalMode;
	}

	@Override
	public boolean acceptsNode(GTreeNode node) {
		if (filters.isEmpty()) {
			return true;
		}

		List<String> nodeData = transformer.transform(node);
		Stream<TextFilter> stream = filters.stream();
		if (evalMode == MultitermEvaluationMode.AND) {
			return stream.allMatch(f -> matches(f, nodeData));
		}
		return stream.anyMatch(f -> matches(f, nodeData));
	}

	@Override
	public boolean showFilterMatches() {
		return true;
	}

	private static boolean matches(TextFilter filter, List<String> nodeData) {
		return nodeData.stream().anyMatch(data -> filter.matches(data));
	}

}
