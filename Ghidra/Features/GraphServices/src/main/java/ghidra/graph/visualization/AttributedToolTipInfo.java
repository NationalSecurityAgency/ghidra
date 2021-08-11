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
package ghidra.graph.visualization;

import java.awt.event.MouseEvent;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JToolTip;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

import com.google.common.base.Splitter;

import ghidra.graph.viewer.popup.ToolTipInfo;
import ghidra.service.graph.*;

/**
 * Generates tool tips for an {@link AttributedVertex} or {@link AttributedEdge} in 
 * an {@link AttributedGraph}
 */
public class AttributedToolTipInfo extends ToolTipInfo<Attributed> {

	AttributedToolTipInfo(Attributed graphObject, MouseEvent event) {
		super(event, graphObject);
	}

	@Override
	public JComponent createToolTipComponent() {
		if (graphObject == null) {
			return null;
		}

		String toolTip = getToolTipText();
		if (StringUtils.isBlank(toolTip)) {
			return null;
		}

		JToolTip jToolTip = new JToolTip();
		jToolTip.setTipText(toolTip);
		return jToolTip;
	}

	@Override
	protected void emphasize() {
		// this graph display does not have a notion of emphasizing
	}

	@Override
	protected void deEmphasize() {
		// this graph display does not have a notion of emphasizing
	}

	/**
	 * Returns the tool tip for the graphObject this object manages
	 * @return  the tool tip for the graphObject this object manages
	 */
	public String getToolTipText() {
		String tooltipText = graphObject.getDescription();
		if (tooltipText != null) {
			return tooltipText;
		}

		StringBuilder buf = new StringBuilder();
		buf.append("<HTML>");

		if (graphObject instanceof AttributedVertex) {
			addToolTipTextForVertex(buf, (AttributedVertex) graphObject);
		}
		else if (graphObject instanceof AttributedEdge) {
			addToolTipTextForEdge(buf, (AttributedEdge) graphObject);
		}
		return buf.toString();
	}

	private void addToolTipTextForVertex(StringBuilder buf, AttributedVertex vertex) {
		String vertexType = vertex.getVertexType();

		buf.append("<H4>");
		buf.append(vertex.getName());
		if (vertexType != null) {
			buf.append("<br>");
			buf.append("Type: &nbsp;" + vertexType);
		}
		buf.append("</H4>");

		addAttributes(buf, AttributedVertex.NAME_KEY, AttributedVertex.VERTEX_TYPE_KEY);
	}

	private void addToolTipTextForEdge(StringBuilder buf, AttributedEdge edge) {
		String edgeType = edge.getEdgeType();
		if (edgeType != null) {
			buf.append("<H4>");
			buf.append("Type: &nbsp;" + edgeType);
			buf.append("</H4>");
		}
		addAttributes(buf, AttributedEdge.EDGE_TYPE_KEY);
	}

	private void addAttributes(StringBuilder buf, String...excludedKeys) {
		
		Set<Entry<String, String>> entries = graphObject.entrySet();

		for (Map.Entry<String, String> entry : entries) {
			String key = entry.getKey();
			if (ArrayUtils.contains(excludedKeys, key)) {
				continue; // skip keys handled in header
			}
			buf.append(key);
			buf.append(": ");
			String value = entry.getValue();
			value = StringEscapeUtils.escapeHtml4(value);
			String split = String.join("<br>", Splitter.on('\n').split(value));
			split = split.replaceAll("\\s", "&nbsp;");
			buf.append(split);
			buf.append("<br>");
		}
	}

}
