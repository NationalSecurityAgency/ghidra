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
package ghidra.graph.viewer.event.mouse;

import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

public class VisualGraphSatelliteNavigationGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphSatelliteAbstractGraphMousePlugin<V, E> {

	public VisualGraphSatelliteNavigationGraphMousePlugin() {
		super(InputEvent.BUTTON1_DOWN_MASK);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		boolean accepted = checkModifiers(e);
		if (!accepted) {
			return;
		}

		isHandlingMouseEvents = true;
		e.consume();

		moveMasterViewerToMousePoint(e);
	}
}
