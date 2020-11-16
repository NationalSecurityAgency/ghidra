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

import java.awt.Point;
import java.awt.event.*;

import docking.DockingUtils;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import ghidra.graph.viewer.*;

public class VisualGraphScreenPositioningPlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin
		implements MouseWheelListener, VisualGraphMousePlugin<V, E> {

	public VisualGraphScreenPositioningPlugin() {
		super(0);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {
		int eventModifiers = e.getModifiersEx();
		boolean controlKeyDown = (eventModifiers & DockingUtils.CONTROL_KEY_MODIFIER_MASK) != 0;
		if (!controlKeyDown) {
			return;
		}

		int wheelRotation = -e.getWheelRotation();
		int offset = wheelRotation * 10;

		Point newPoint = new Point(0, offset);

		if (e.isAltDown()) {
			// control-alt is a horizontal pan
			newPoint.setLocation(offset, 0);
		}

		VisualGraphViewUpdater<V, E> updater = getViewUpdater(e);
		updater.moveViewerLocationWithoutAnimation(newPoint);
	}
}
