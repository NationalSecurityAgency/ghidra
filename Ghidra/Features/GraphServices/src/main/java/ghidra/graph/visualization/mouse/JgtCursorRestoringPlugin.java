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

import java.awt.Cursor;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;

import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.AbstractGraphMousePlugin;

/**
 * Restores the cursor after other graph mouse operations.
 * 
 * Future: this is copied from the Visual Graph counterpart--consolidate these
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JgtCursorRestoringPlugin<V, E> extends AbstractGraphMousePlugin
		implements MouseMotionListener {

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
