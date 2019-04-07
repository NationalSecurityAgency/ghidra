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
package ghidra.app.plugin.core.functiongraph.graph.jung.renderer;

import java.awt.Color;
import java.awt.Paint;

import com.google.common.base.Function;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.program.model.symbol.FlowType;

public class FGEdgePaintTransformer implements Function<FGEdge, Paint> {

	private FunctionGraphOptions options;

	public FGEdgePaintTransformer(FunctionGraphOptions options) {
		this.options = options;
	}

	@Override
	public Paint apply(FGEdge e) {
		FlowType flowType = e.getFlowType();
		Color color = options.getColor(flowType);
		return color;
	}
}
