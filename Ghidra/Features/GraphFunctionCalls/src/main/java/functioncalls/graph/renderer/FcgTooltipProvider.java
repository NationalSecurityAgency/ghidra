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
package functioncalls.graph.renderer;

import java.awt.Component;
import java.awt.event.MouseEvent;

import javax.swing.*;

import functioncalls.graph.FcgEdge;
import functioncalls.graph.FcgVertex;
import ghidra.graph.viewer.event.mouse.VertexTooltipProvider;

/**
 * A class that provides tooltips for a given vertex
 */
public class FcgTooltipProvider implements VertexTooltipProvider<FcgVertex, FcgEdge> {

	@Override
	public JComponent getTooltip(FcgVertex v) {
		JToolTip tip = new JToolTip();
		tip.setTipText(v.getName());
		return tip;
	}

	@Override
	public JComponent getTooltip(FcgVertex v, FcgEdge e) {
		return null;
	}

	@Override
	public String getTooltipText(FcgVertex v, MouseEvent e) {
		// TODO we could have the name label return just the function name; the vertex shape
		//      return a full function signature and the +/- toggle buttons return a tip

		Component child = e.getComponent();

		// the buttons may have extra information
		if (child instanceof JButton) {
			return ((JButton) child).getToolTipText();
		}

		return v.getName();
	}

}
