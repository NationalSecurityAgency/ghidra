/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.list;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;

/**
 * A listener designed to forward events from a JList to its renderer.  This listener allows
 * renderers to embed components in the renderer and gives them the mouse events they need to 
 * interact with the user.
 */
public class ListRendererMouseEventForwarder extends MouseAdapter {

	@Override
	public void mouseMoved(MouseEvent e) {
		redispatchEvent(e);
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		redispatchEvent(e);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		redispatchEvent(e);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		redispatchEvent(e);
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		redispatchEvent(e);
	}

	@Override
	public void mouseClicked(MouseEvent event) {
		redispatchEvent(event);
	}

	private void redispatchEvent(MouseEvent event) {
		JList list = (JList) event.getSource();
		int index = list.locationToIndex(event.getPoint());
		Rectangle cellBounds = list.getCellBounds(index, index);
		if (cellBounds == null) {
			return;
		}

		ListModel model = list.getModel();
		Object state = model.getElementAt(index);

		ListCellRenderer renderer = list.getCellRenderer();
		Component rendererComponent =
			renderer.getListCellRendererComponent(list, state, index, true, true);
		rendererComponent.setBounds(cellBounds);

		Point p = event.getPoint();
		p.translate(-cellBounds.x, -cellBounds.y);

		MouseEvent newEvent =
			new MouseEvent(rendererComponent, event.getID(), event.getWhen(), event.getModifiers(),
				p.x, p.y, event.getXOnScreen(), event.getYOnScreen(), event.getClickCount(),
				event.isPopupTrigger(), event.getButton());

		rendererComponent.dispatchEvent(newEvent);
		list.repaint();
	}
}
