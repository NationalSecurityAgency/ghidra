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
package docking.widgets.filter;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Rectangle2D;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import docking.util.AnimationUtils;
import docking.widgets.label.GIconLabel;
import ghidra.util.SystemUtilities;
import resources.Icons;
import resources.ResourceManager;

/**
 * A label that displays an icon that, when clicked, will clear the contents of the 
 * associated filter.
 */
public class ClearFilterLabel extends GIconLabel {

	private Icon RAW_ICON = Icons.DELETE_ICON;
	private Icon ICON = ResourceManager.getScaledIcon(RAW_ICON, 10, 10);

	private static final float FULLY_TRANSPARENT = 0F;
	private static final float FULLY_OPAQUE = .6F;
	private static final float PARTIALLY_HIDDEN = .2F;
	private static final int FADE_IN_MS = 1500;

	private JTextField textField;
	private float transparency;
	private Animator animator;

	public ClearFilterLabel(JTextField textField) {

		this.textField = textField;

		// pad some to offset from the edge of the text field
		setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));

		textField.getDocument().addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				resetBounds();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				resetBounds();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				resetBounds();
			}
		});

		textField.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				resetBounds();
			}
		});

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				clearFilter();
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

		setIcon(ICON);
		setToolTipText("Clear filter");
	}

	private void clearFilter() {
		textField.setText("");
		cancelAnimation();
	}

	@Override
	protected void paintComponent(Graphics g) {

		Graphics2D g2d = (Graphics2D) g;
		Composite oldComposite = g2d.getComposite();

		try {
			AlphaComposite alpha =
				AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), transparency);
			g2d.setComposite(alpha);

			super.paintComponent(g);
		}
		finally {
			g2d.setComposite(oldComposite);
		}
	}

	public void setTransparency(float transparency) {
		this.transparency = transparency;
		repaint();
	}

	public void showFilterButton() {

		if (isVisible()) {
			return;
		}

		this.transparency = FULLY_TRANSPARENT;
		setVisible(true);

		reanimate();
	}

	private void reanimate() {

		if (!AnimationUtils.isAnimationEnabled()) {
			transparency = FULLY_OPAQUE;
			return;
		}

		if (animator != null) {
			return; // already animating
		}

		animator = PropertySetter.createAnimator(FADE_IN_MS, this, "transparency",
			FULLY_TRANSPARENT, FULLY_OPAQUE);
		animator.setAcceleration(0f);
		animator.setDeceleration(0.8f);

		animator.addTarget(new TimingTargetAdapter() {
			@Override
			public void end() {
				animator = null;
			}
		});

		animator.start();
	}

	private void cancelAnimation() {
		if (animator != null) {
			animator.cancel();
			animator = null;
		}
	}

	public void hideFilterButton() {
		cancelAnimation();
		setVisible(false);
	}

	private void resetBounds() {
		SystemUtilities.runIfSwingOrPostSwingLater(() -> doResetBounds());
	}

	private void doResetBounds() {
		// My bounds are tied to that of the text field passed in the constructor.  I'd like
		// to live at the end of the textField, away from the text, which is dependent upon 
		// the text alignment
		Container myParent = getParent();
		if (myParent == null) {
			return; // initializing
		}

		Rectangle textBounds = textField.getBounds();
		Insets textInsets = textField.getInsets();
		Point location = textBounds.getLocation();

		Dimension size = getPreferredSize();
		int half = (textBounds.height - size.height) / 2;
		int y = textBounds.y + half;

		int end = location.x + textBounds.width;
		int x = end - textInsets.right - size.width;

		// hide when text is near
		checkForTouchyText(x);

		setBounds(x, y, size.width, size.height);

		myParent.validate();
	}

	private void checkForTouchyText(int x) {

		if (touchesText(x)) {
			// don't let this label block the text
			transparency = PARTIALLY_HIDDEN;
			return;
		}

		// not touching...
		if (transparency == PARTIALLY_HIDDEN) {
			// restore
			transparency = FULLY_OPAQUE;
		}
	}

	private boolean touchesText(int x) {

		FontMetrics fm = textField.getFontMetrics(textField.getFont());

		Rectangle textBounds = textField.getBounds();
		Point location = textBounds.getLocation();

		String text = textField.getText();
		Rectangle2D bounds = fm.getStringBounds(text, textField.getGraphics());
		double textWidth = bounds.getWidth() + bounds.getX();

		int padding = 5;
		if (location.x + textWidth + padding > x) {
			return true;
		}
		return false;
	}
}
