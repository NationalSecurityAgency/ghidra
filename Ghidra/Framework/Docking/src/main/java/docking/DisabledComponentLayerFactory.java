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
package docking;

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.plaf.LayerUI;

/**
 * A factory to create JLayer instances to provide the L&amp;F and functionality of a 
 * disabled panel -- the component assumes a disabled color, and selection via mouse and
 * keyboard is prevented. As this is simply a layer in the UI stack, previous states of 
 * components is maintained and unmodified.
 */
public class DisabledComponentLayerFactory {

	private static DisabledComponentLayerUI disabledUI = new DisabledComponentLayerUI();

	private DisabledComponentLayerFactory() {
	}

	public static JLayer<JComponent> getDisabledLayer(JComponent component) {
		JLayer<JComponent> layer = new JLayer<JComponent>(component, disabledUI);

		return layer;
	}

	private static class DisabledComponentLayerUI extends LayerUI<JComponent> {

		@Override
		public void installUI(JComponent c) {
			super.installUI(c);
			JLayer<?> l = (JLayer<?>) c;
			l.setLayerEventMask(
				AWTEvent.KEY_EVENT_MASK | AWTEvent.FOCUS_EVENT_MASK | AWTEvent.MOUSE_EVENT_MASK);
		}

		@Override
		public void uninstallUI(JComponent c) {
			super.uninstallUI(c);
			JLayer<?> l = (JLayer<?>) c;
			// JLayer must be returned to its initial state
			l.setLayerEventMask(0);
		}

		private Color getColorForComponent(JComponent comp) {
			if (comp instanceof AbstractButton) {
				return UIManager.getColor("Button.background");
			}
			else if (comp instanceof JComboBox) {
				return UIManager.getColor("ComboBox.background");
			}
			else if (comp instanceof JMenu) {
				return UIManager.getColor("Menu.background");
			}
			else if (comp instanceof JMenuBar) {
				return UIManager.getColor("MenuBar.background");
			}
			else if (comp instanceof JMenuItem) {
				return UIManager.getColor("MenuItem.background");
			}
			return UIManager.getColor("Panel.background");
		}

		@Override
		public void paint(Graphics g, JComponent c) {
			super.paint(g, c);

			if (c.isEnabled()) {
				return;
			}

			Color disabledColor = getColorForComponent(c);

			Graphics2D g2 = (Graphics2D) g.create();

			int w = c.getWidth();
			int h = c.getHeight();
			g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, .5f));
			g2.setPaint(disabledColor);
			g2.fillRect(0, 0, w, h);

			g2.dispose();
		}

		@Override
		public void eventDispatched(AWTEvent e, JLayer<? extends JComponent> layer) {

			boolean block = !layer.isEnabled();

			if (block) {
				if (e instanceof FocusEvent) {
					return;
				}
				else if (e instanceof MouseEvent) {
					((MouseEvent) e).consume();
					return;
				}
				else if (e instanceof KeyEvent) {
					((KeyEvent) e).consume();
					return;
				}
			}

			super.eventDispatched(e, layer);
		}

	}
}
