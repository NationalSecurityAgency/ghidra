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

import java.awt.Cursor;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;

public class VisualGraphCursorRestoringGraphMousePlugin<V, E> extends AbstractGraphMousePlugin
		implements MouseMotionListener {

	public VisualGraphCursorRestoringGraphMousePlugin() {
		super(0);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		installCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR), e);
	}

	@SuppressWarnings("unchecked")
	private void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		viewer.setCursor(newCursor);
	}
}
