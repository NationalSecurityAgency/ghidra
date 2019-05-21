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
package ghidra.feature.vt.gui.filters;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.feature.vt.gui.filters.Filter.FilterEditingStatus;

public class StatusLabel extends GDLabel implements FilterStatusListener {

	private final JFormattedTextField textField;

	public StatusLabel(final JFormattedTextField textField, final Object defaultValue) {
		this.textField = textField;
		textField.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(java.awt.event.ComponentEvent e) {
				resetBounds();
			}
		});
		setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				textField.setValue(defaultValue);
			}

			@Override
			public void mouseEntered(MouseEvent e) {
				setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
			}

			@Override
			public void mouseExited(MouseEvent e) {
				setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			}
		});
	}

	private void resetBounds() {
		// My bounds are tied to that of the text field passed in the constructor.  I'd like
		// to live at the end of the textField, away from the text, which is dependent upon 
		// the text alignment
		Container myParent = getParent();
		Container textFieldParent = textField.getParent();
		Rectangle textBounds = textField.getBounds();
		Point textFieldLocation = textBounds.getLocation();
		Point convertedLocation =
			SwingUtilities.convertPoint(textFieldParent, textFieldLocation, myParent);

		int alignment = textField.getHorizontalAlignment();
		if (alignment == SwingConstants.RIGHT || alignment == SwingConstants.TRAILING) {
			Dimension size = getPreferredSize();
			int x = convertedLocation.x;// + size.width;
			int y = convertedLocation.y; // try this for now...maybe center?                
			setBounds(x, y, size.width, size.height);
		}
		else if (alignment == SwingConstants.LEFT || alignment == SwingConstants.LEADING) {
			Dimension size = getPreferredSize();
			int x = (convertedLocation.x + textBounds.width) - size.width;
			int y = convertedLocation.y; // try this for now...maybe center?
			setBounds(x, y, size.width, size.height);
		}
	}

	@Override
	public void filterStatusChanged(FilterEditingStatus status) {
		resetBounds();
		setIcon(status.getIcon());
		setToolTipText(status.getDescription() + " (click to reset)");
	}
}
