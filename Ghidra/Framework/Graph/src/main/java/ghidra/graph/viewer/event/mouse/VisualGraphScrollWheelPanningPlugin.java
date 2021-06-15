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
import ghidra.graph.viewer.options.VisualGraphOptions;

//@formatter:off
public class VisualGraphScrollWheelPanningPlugin<V extends VisualVertex, 
												   E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin 
		implements MouseWheelListener, VisualGraphMousePlugin<V, E> {
//@formatter:on	

	public VisualGraphScrollWheelPanningPlugin() {
		super(0);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {
		if (!isScrollModifiers(e)) {
			return;
		}

		pan(e);
	}

	private void pan(MouseWheelEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);

		//
		// Number of 'units' by which to scroll.  This is defined by the OS and is usually
		// something like 'lines of text'.
		//
		int scrollAmount = 1;
		if (e.getScrollType() == MouseWheelEvent.WHEEL_UNIT_SCROLL) {
			scrollAmount = e.getScrollAmount();
		}

		//
		// The amount the mouse wheel has been rotated.  By default this is usually 1, but 
		// users can change how the OS accelerates mouse scrolling.
		//
		int wheelRotation = -e.getWheelRotation();

		//
		// A magic magnification amount.  This was chosen by testing on a few platforms.
		//
		int arbitraryAcceleration = 10;

		//
		// The scale of the current graph.  We need to change the scroll amount when scaled out
		// so that we don't end up with tiny scrolling when zoomed out.
		//		
		Double scale = GraphViewerUtils.getGraphScale(viewer);
		int unscaledOffset = wheelRotation * scrollAmount * arbitraryAcceleration;
		int offset = (int) (unscaledOffset * (1 / scale));

		Point newPoint = new Point(0, offset);

		if (e.isAltDown()) {
			// control-alt is a horizontal pan
			newPoint.setLocation(offset, 0);
		}

		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		updater.moveViewerLocationWithoutAnimation(newPoint);
	}

	private boolean isScrollModifiers(MouseWheelEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		VisualGraphOptions options = viewer.getOptions();
		boolean scrollWheelPans = options.getScrollWheelPans();
		int scrollWheelModifierToggle = DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		int eventModifiers = e.getModifiersEx();
		if (scrollWheelPans) {
			// scrolling will pan if *not* modified (modified in this case means to zoom)
			return !((scrollWheelModifierToggle & eventModifiers) == scrollWheelModifierToggle);
		}

		// scrolling *will* pan only when modified (unmodified in this case means to zoom)
		return ((scrollWheelModifierToggle & eventModifiers) == scrollWheelModifierToggle);
	}

}
