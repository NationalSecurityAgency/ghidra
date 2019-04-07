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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.event.MouseEvent;

import javax.swing.JComponent;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;

public class FGVertexTooltipProvider implements VertexTooltipProvider<FGVertex, FGEdge> {

	@Override
	public JComponent getTooltip(FGVertex v) {
		JComponent c = v.getToolTipComponentForVertex();
		return c;
	}

	@Override
	public JComponent getTooltip(FGVertex v, FGEdge e) {
		JComponent c = v.getToolTipComponentForEdge(e);
		return c;
	}

	@Override
	public String getTooltipText(FGVertex v, MouseEvent e) {
		String tooltip = v.getToolTipText(e);
		return tooltip;
	}

}
