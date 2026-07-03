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
import java.awt.event.*;
import java.beans.PropertyEditorSupport;

import javax.swing.JPanel;
import javax.swing.SwingConstants;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GDHtmlLabel;
import ghidra.util.ColorUtils;
import ghidra.util.WebColors;

/**
 * Color editor that is a bit unusual in that its custom component is a label that when clicked,
 * pops up a dialog for editing the color. Use {@link ColorPropertyEditor} for a more traditional
 * property editor that returns a direct color editing component.
 */
public class ColorEditor extends PropertyEditorSupport {

	private static GhidraColorChooser colorChooser;

	private FocusableLabel previewLabel = new FocusableLabel();
	private Color color;
	private Color lastUserSelectedColor;

	public ColorEditor() {
	}

	private void triggerEdit() {
		// show the editor to get the user value
		showDialog(previewLabel);

		ColorEditor.this.firePropertyChange();

		// now set the new value
		updateColor(color);
	}

	private void showDialog(Component parentComponent) {
		JPanel dialogPanel = new JPanel();
		dialogPanel.setLayout(new BorderLayout());
		dialogPanel.add(new ColorEditorPanel(), BorderLayout.CENTER);
		dialogPanel.getAccessibleContext().setAccessibleName(parentComponent.getName());
		EditorProvider provider = new EditorProvider(dialogPanel);
		DockingWindowManager.showDialog(previewLabel, provider);
	}

	@Override
	public Component getCustomEditor() {
		return previewLabel;
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public void setValue(Object value) {
		color = (Color) value;
		lastUserSelectedColor = color;
		updateColor(color);
	}

	private void updateColor(Color newColor) {

		// change the color to a darker value if the color being set is light
		String colorString =
			WebColors.toString(ColorUtils.contrastForegroundColor(newColor), false);
		previewLabel.setText(
			"<html><CENTER><I><FONT SIZE=2 COLOR=" + colorString + ">click</FONT></I></CENTER>");

		previewLabel.setBackground(color);
	}

	@Override
	public Object getValue() {
		return color;
	}

	@Override
	public boolean isPaintable() {
		return false;
	}

	private class EditorProvider extends DialogComponentProvider {
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

	private class ColorEditorPanel extends JPanel {

		ColorEditorPanel() {

			setLayout(new BorderLayout());

			if (colorChooser == null) {
				colorChooser = new GhidraColorChooser();
			}

			add(colorChooser, BorderLayout.CENTER);
			colorChooser.getSelectionModel().addChangeListener(e -> {

				// This could be a ColorUIResource, but Options only support storing Color.  So,
				// manually create a new Color object to avoid saving a ColorUIResource.
				Color c = colorChooser.getColor();
				lastUserSelectedColor = ColorUtils.getColor(c.getRGB());
			});
			colorChooser.setColor(color);
		}
	}

	private class FocusableLabel extends GDHtmlLabel {

		FocusableLabel() {
			setOpaque(true);
			setFocusable(true);
			setPreferredSize(new Dimension(100, 20));
			setHorizontalAlignment(SwingConstants.CENTER);
			getAccessibleContext().setAccessibleName("Preview");
			addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					triggerEdit();
				}
			});
			addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_SPACE) {
						triggerEdit();
						e.consume();
					}
				}
			});
			addFocusListener(new FocusListener() {
				@Override
				public void focusGained(FocusEvent e) {
					repaint();
				}

				@Override
				public void focusLost(FocusEvent e) {
					repaint();
				}
			});
		}

		@Override
		public void paint(Graphics g) {

			super.paint(g);

			if (!hasFocus()) {
				return;
			}

			Color otherColor = ColorUtils.contrastForegroundColor(color);
			g.setColor(otherColor);

			Dimension size = getSize();
			int offset = 4;
			int x = offset;
			int y = offset;
			int w = size.width - (2 * offset);
			int h = size.height - (2 * offset);
			g.drawRect(x, y, w, h);
		}

	}
}
