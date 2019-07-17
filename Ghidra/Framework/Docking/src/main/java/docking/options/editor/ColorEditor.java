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
package docking.options.editor;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.beans.PropertyEditorSupport;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GDHtmlLabel;

/**
 * Color editor that uses the JColorChooser.
 */
public class ColorEditor extends PropertyEditorSupport {

	private static final String LIGHT_COLOR = "SILVER";
	private static final String DARK_COLOR = "BLACK";

	private static GhidraColorChooser colorChooser;

	private JLabel previewLabel = new GDHtmlLabel();
	private Color color;
	private Color lastUserSelectedColor;

	/**
	 * The default constructor.
	 *
	 */
	public ColorEditor() {
		previewLabel.setOpaque(true);
		previewLabel.setPreferredSize(new Dimension(100, 20));
		previewLabel.setHorizontalAlignment(SwingConstants.CENTER);
		previewLabel.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent evt) {
				// show the editor to get the user value
				showDialog(evt.getComponent());

				ColorEditor.this.firePropertyChange();

				// now set the new value
				updateColor(color);
			}
		});
	}

	private void showDialog(Component parentComponent) {
		JPanel dialogPanel = new JPanel();
		dialogPanel.setLayout(new BorderLayout());
		dialogPanel.add(new ColorEditorPanel(), BorderLayout.CENTER);
		EditorProvider provider = new EditorProvider(dialogPanel);
		DockingWindowManager.showDialog(previewLabel, provider);
	}

	/**
	 * A PropertyEditor may chose to make available a full custom Component
	 * that edits its property value.  It is the responsibility of the
	 * PropertyEditor to hook itself up to its editor Component itself and
	 * to report property value changes by firing a PropertyChange event.
	 * <P>
	 * The higher-level code that calls getCustomEditor may either embed
	 * the Component in some larger property sheet, or it may put it in
	 * its own individual dialog, or ...
	 *
	 * @return A java.awt.Component that will allow a human to directly
	 *      edit the current property value.  May be null if this is
	 *	    not supported.
	 */
	@Override
	public Component getCustomEditor() {
		return previewLabel;
	}

	/**
	 * Determines whether the propertyEditor can provide a custom editor.
	 *
	 * @return  True if the propertyEditor can provide a custom editor.
	 */
	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	/**
	 * Set (or change) the object that is to be edited.
	 * @param value The new target object to be edited.  Note that this
	 *     object should not be modified by the PropertyEditor, rather
	 *     the PropertyEditor should create a new object to hold any
	 *     modified value.
	 */
	@Override
	public void setValue(Object value) {
		color = (Color) value;
		lastUserSelectedColor = color;
		updateColor(color);
	}

	private void updateColor(Color newColor) {
		String colorString = LIGHT_COLOR;

		// change the color to a darker value if the color being set is light
		int colorValue = newColor.getRed() + newColor.getGreen() + newColor.getBlue();
		if (colorValue > 400) {  // arbitrary threshold determined by trial-and-error
			colorString = DARK_COLOR;
		}

		previewLabel.setText(
			"<HTML><CENTER><I><FONT SIZE=2 COLOR=" + colorString + ">click</FONT></I></CENTER>");

		previewLabel.setBackground(color);
	}

	/**
	 * Get the value.
	 */
	@Override
	public Object getValue() {
		return color;
	}

	/**
	 * Return true which this editor can paint its property value.
	 */
	@Override
	public boolean isPaintable() {
		return false;
	}

	/**
	 * Paint a representation of the value into a given area of screen
	 * real estate.  Note that the propertyEditor is responsible for doing
	 * its own clipping so that it fits into the given rectangle.
	 * <p>
	 * If the PropertyEditor doesn't honor paint requests (see isPaintable)
	 * this method should be a silent noop.
	 *
	 * @param gfx  Graphics object to paint into.
	 * @param box  Rectangle within graphics object into which we should paint.
	 */
	@Override
	public void paintValue(Graphics gfx, Rectangle box) {
		if (color != null) {
			gfx.setColor(color);
		}
		else {
			gfx.setColor(Color.black);
		}
		gfx.fillRect(box.x, box.y, box.width, box.height);
	}

	/////////////////////////////////////////////////////////////////////////

	class EditorProvider extends DialogComponentProvider {
		EditorProvider(JPanel contentPanel) {
			super("Color Editor", true);

			addWorkPanel(contentPanel);
			addOKButton();
			addCancelButton();
		}

		@Override
		protected void okCallback() {
			color = lastUserSelectedColor;
			close();
		}
	}

	class ColorEditorPanel extends JPanel {

		ColorEditorPanel() {

			setLayout(new BorderLayout());

			if (colorChooser == null) {
				colorChooser = new GhidraColorChooser();
			}

			add(colorChooser, BorderLayout.CENTER);
			colorChooser.getSelectionModel().addChangeListener(new ChangeListener() {
				@Override
				public void stateChanged(ChangeEvent e) {
					lastUserSelectedColor = colorChooser.getColor();
					// This could be a ColorUIResource, but Options only support storing Color.
					lastUserSelectedColor =
						new Color(lastUserSelectedColor.getRed(), lastUserSelectedColor.getGreen(),
							lastUserSelectedColor.getBlue(), lastUserSelectedColor.getAlpha());
				}
			});
			colorChooser.setColor(color);
		}
	}
}
