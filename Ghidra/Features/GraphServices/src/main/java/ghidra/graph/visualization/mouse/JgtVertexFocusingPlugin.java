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
package ghidra.graph.visualization.mouse;

import java.awt.event.MouseEvent;

import ghidra.graph.visualization.DefaultGraphDisplay;
import ghidra.service.graph.AttributedVertex;

/**
 * A mouse plugin to focus a vertex when clicked
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JgtVertexFocusingPlugin<V, E> extends AbstractJgtGraphMousePlugin<V, E> {

	private DefaultGraphDisplay graphDisplay;
	protected int singleSelectionMask;

	public JgtVertexFocusingPlugin(int singleSelectionMask, DefaultGraphDisplay graphDisplay) {
		this.singleSelectionMask = singleSelectionMask;
		this.graphDisplay = graphDisplay;
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == singleSelectionMask;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}

		selectedVertex = getVertex(e);
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (selectedVertex == null) {
			return;
		}

		graphDisplay.setFocusedVertex((AttributedVertex) selectedVertex);

		// Note: do not consume the event.  We will just focus our vertex, regardless of further
		//       mouse event processing.
	}
}
