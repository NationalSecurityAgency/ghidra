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
package docking.widgets;

import java.awt.*;

import javax.swing.JComponent;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

/**
 * A helper class to the InlineComponentTitledPanel that implements the component-in-border effect.
 * <p>
 * <b>This class should not be used outside InlineComponentTitledPanel.</b>
 *  @see docking.widgets.InlineComponentTitledPanel
 */
class InlineComponentTitledBorder extends TitledBorder {

	protected JComponent component;

	public InlineComponentTitledBorder(JComponent component) {
		this(null, component, LEFT, TOP);
	}

	public InlineComponentTitledBorder(Border border) {
		this(border, null, LEFT, TOP);
	}

	public InlineComponentTitledBorder(Border border, JComponent component) {
		this(border, component, LEFT, TOP);
	}

	public InlineComponentTitledBorder(Border border, JComponent component, int titleJustification,
			int titlePosition) {
		super(border, null, titleJustification, titlePosition, null, null);
		this.component = component;
		if (border == null) {
			this.border = super.getBorder();
		}
	}

	@Override
	public void paintBorder(Component c, Graphics g, int x, int y, int width, int height) {

		Rectangle borderR = new Rectangle(x + EDGE_SPACING, y + EDGE_SPACING,
			width - (EDGE_SPACING * 2), height - (EDGE_SPACING * 2));
		Insets borderInsets;
		if (border != null) {
			borderInsets = border.getBorderInsets(c);
		}
		else {
			borderInsets = new Insets(0, 0, 0, 0);
		}

		Rectangle rect = new Rectangle(x, y, width, height);
		Insets insets = getBorderInsets(c);
		Rectangle compR = getComponentRect(rect, insets);
		int diff;
		switch (titlePosition) {
			default:
			case ABOVE_TOP:
				diff = compR.height + TEXT_SPACING;
				borderR.y += diff;
				borderR.height -= diff;
				break;
			case TOP:
			case DEFAULT_POSITION:
				diff = insets.top / 2 - borderInsets.top - EDGE_SPACING;
				borderR.y += diff;
				borderR.height -= diff;
				break;
			case BELOW_TOP:
			case ABOVE_BOTTOM:
				break;
			case BOTTOM:
				diff = insets.bottom / 2 - borderInsets.bottom - EDGE_SPACING;
				borderR.height -= diff;
				break;
			case BELOW_BOTTOM:
				diff = compR.height + TEXT_SPACING;
				borderR.height -= diff;
				break;
		}
		border.paintBorder(c, g, borderR.x, borderR.y, borderR.width, borderR.height);
		Color col = g.getColor();
		g.setColor(c.getBackground());
		g.fillRect(compR.x, compR.y, compR.width, compR.height);
		g.setColor(col);
		component.repaint();
	}

	@Override
	public Insets getBorderInsets(Component c, Insets insets) {
		Insets borderInsets;
		if (border != null) {
			borderInsets = border.getBorderInsets(c);
		}
		else {
			borderInsets = new Insets(0, 0, 0, 0);
		}
		insets.top = EDGE_SPACING + TEXT_SPACING + borderInsets.top;
		insets.right = EDGE_SPACING + TEXT_SPACING + borderInsets.right;
		insets.bottom = EDGE_SPACING + TEXT_SPACING + borderInsets.bottom;
		insets.left = EDGE_SPACING + TEXT_SPACING + borderInsets.left;

		if (c == null || component == null) {
			return insets;
		}

		int compHeight = 0;
		if (component != null) {
			compHeight = component.getPreferredSize().height;
		}

		switch (titlePosition) {
			default:
			case ABOVE_TOP:
				insets.top += compHeight + TEXT_SPACING;
				break;
			case TOP:
			case DEFAULT_POSITION:
				insets.top += Math.max(compHeight, borderInsets.top) - borderInsets.top;
				break;
			case BELOW_TOP:
				insets.top += compHeight + TEXT_SPACING;
				break;
			case ABOVE_BOTTOM:
				insets.bottom += compHeight + TEXT_SPACING;
				break;
			case BOTTOM:
				insets.bottom += Math.max(compHeight, borderInsets.bottom) - borderInsets.bottom;
				break;
			case BELOW_BOTTOM:
				insets.bottom += compHeight + TEXT_SPACING;
				break;
		}
		return insets;
	}

	public JComponent getTitleComponent() {
		return component;
	}

	public void setTitleComponent(JComponent component) {
		this.component = component;
	}

	public Rectangle getComponentRect(Rectangle rect, Insets borderInsets) {
		Dimension compD = component.getPreferredSize();
		Rectangle compR = new Rectangle(0, 0, compD.width, compD.height);
		switch (titlePosition) {
			default:
			case ABOVE_TOP:
				compR.y = EDGE_SPACING;
				break;
			case TOP:
			case DEFAULT_POSITION:
				compR.y = EDGE_SPACING +
					(borderInsets.top - EDGE_SPACING - TEXT_SPACING - compD.height) / 2;
				break;
			case BELOW_TOP:
				compR.y = borderInsets.top - compD.height - TEXT_SPACING;
				break;
			case ABOVE_BOTTOM:
				compR.y = rect.height - borderInsets.bottom + TEXT_SPACING;
				break;
			case BOTTOM:
				compR.y = rect.height - borderInsets.bottom + TEXT_SPACING +
					(borderInsets.bottom - EDGE_SPACING - TEXT_SPACING - compD.height) / 2;
				break;
			case BELOW_BOTTOM:
				compR.y = rect.height - compD.height - EDGE_SPACING;
				break;
		}
		switch (titleJustification) {
			default:
			case LEFT:
			case DEFAULT_JUSTIFICATION:
				compR.x = TEXT_INSET_H + borderInsets.left;
				break;
			case RIGHT:
				compR.x = rect.width - borderInsets.right - TEXT_INSET_H - compR.width;
				break;
			case CENTER:
				compR.x = (rect.width - compR.width) / 2;
				break;
		}
		return compR;
	}
}
