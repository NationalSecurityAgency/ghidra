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
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

/**
 * A panel with a component-containing border. Use a checkbox as the component, for example, 
 * to control the enablement of child widgets.
 * <p> 
 *  Users should modify the contents of this panel via the JPanel from <code>getContentPane()</code> 
 *  -- <code>add()</code> and <code>remove()</code> methods have been overridden to modify the 
 *  content pane; other calls to this panel should <code>getContentPane()</code> first.
 *  <p>
 *  Example:
 *  <pre>
 *  public class MyPanel extends InlineComponentTitledPanel {
 *    private JCheckBox enableCheckbox = null;
 *    public MyPanel() {
 *      super(new JCheckBox("Enable"), BorderFactory.createEtchedBorder());
 *      enableCheckbox = (JCheckBox) getTitleComponent();
 *      enableCheckbox.addActionListener(...);
 *      
 *      JPanel content = getContentPane();
 *      content.setLayout(new BorderLayout());
 *      add(new JButton("Click me"));
 *      ...
 *    }
 *    ...
 *  }</pre>
 *    
 */
public class InlineComponentTitledPanel extends JPanel {

	private JPanel content;
	private InlineComponentTitledBorder border;

	/**
	 * Create a panel with <code>titleComponent</code> in the top, left corner
	 * @param titleComponent widget to draw in the border
	 */
	public InlineComponentTitledPanel(JComponent titleComponent) {
		this(titleComponent, TitledBorder.LEFT, TitledBorder.TOP);
	}

	/**
	 * Create a panel with <code>titleComponent</code> in the top, left corner
	 * @param titleComponent widget to draw in the border
	 * @param otherBorder secondary border to place around this panel
	 */
	public InlineComponentTitledPanel(JComponent titleComponent, Border otherBorder) {
		this(titleComponent, TitledBorder.LEFT, TitledBorder.TOP, otherBorder);
	}

	/**
	 * Create a panel with <code>titleComponent</code> in the prescribed location
	 * @param titleComponent widget to draw in the border
	 * @param titleJustification top-bottom alignment
	 * @param titlePosition left-right alignment
	 * @see TitledBorder
	 */
	public InlineComponentTitledPanel(JComponent titleComponent, int titleJustification,
			int titlePosition) {
		this(titleComponent, titleJustification, titlePosition, BorderFactory.createEmptyBorder());
	}

	/**
	 * Create a panel with <code>titleComponent</code> in the prescribed location with a secondary
	 *  border
	 * @param titleComponent widget to draw in the border
	 * @param titleJustification top-bottom alignment
	 * @param titlePosition left-right alignment
	 * @param otherBorder secondary border to place around this panel
	 * @see TitledBorder
	 */
	public InlineComponentTitledPanel(JComponent titleComponent, int titleJustification,
			int titlePosition, Border otherBorder) {

		Objects.requireNonNull(titleComponent, "InlineComponentTitledPanel requires a component");

		this.border = new InlineComponentTitledBorder(otherBorder, titleComponent, titleJustification,
			titlePosition);

		super.setBorder(border);

		setLayout(new BorderLayout());

		content = new JPanel();

		setTitleComponent(titleComponent);
		super.add(content, BorderLayout.CENTER);

	}

	@Override
	public void doLayout() {
		Insets insets = getInsets();
		Rectangle rect = getBounds();
		rect.x = 0;
		rect.y = 0;

		Rectangle compR = border.getComponentRect(rect, insets);
		getTitleComponent().setBounds(compR);
		rect.x += insets.left;
		rect.y += insets.top;
		rect.width -= insets.left + insets.right;
		rect.height -= insets.top + insets.bottom;
		content.setBounds(rect);
	}

	public JComponent getTitleComponent() {
		return border.getTitleComponent();
	}

	public void setTitleComponent(JComponent component) {
		JComponent existing = getTitleComponent();

		int existingIndex = -1;

		if (existing != null) {
			existingIndex = getComponentIndex(existing);
			if (existingIndex != -1) {
				super.remove(existingIndex);
			}
		}

		border.setTitleComponent(component);
		super.add(component, BorderLayout.CENTER, existingIndex);
	}

	private static final int getComponentIndex(Component component) {
		if (component != null && component.getParent() != null) {
			Container c = component.getParent();
			for (int i = 0; i < c.getComponentCount(); i++) {
				if (c.getComponent(i) == component) {
					return i;
				}
			}
		}

		return -1;
	}

	/**
	 * Sets the secondary border.
	 * 
	 * NOTE: Rendering conflicts may occur with co-located sub-borders; a TitledBorder that 
	 * renders in the same position (top, bottom, etc.) will cause the component to shift, and
	 * will be rendered-over if the new title resides in the same position and justification 
	 * (left-to-right alignment) as the component.
	 * @param otherBorder
	 * @see setOtherBorder(Border)
	 */
	@Override
	public void setBorder(Border otherBorder) {
		setOtherBorder(otherBorder);
	}

	public void setOtherBorder(Border otherBorder) {
		if (border != null) {
			border.setBorder(otherBorder);
		}
		invalidate();
	}

	public Border getOtherBorder() {
		return border.getBorder();
	}

	/**
	 * This class requires that all content be placed within a designated panel, this method returns that panel.
	 *
	 * @return panel The content panel
	 */
	public JPanel getContentPane() {
		return content;
	}

	@Override
	public Component add(Component comp) {
		return content.add(comp);
	}

	@Override
	public Component add(String name, Component comp) {
		return content.add(name, comp);
	}

	@Override
	public Component add(Component comp, int index) {
		return content.add(comp, index);
	}

	@Override
	public void remove(int index) {
		content.remove(index);
	}

	@Override
	public void remove(Component comp) {
		content.remove(comp);
	}

	@Override
	public void removeAll() {
		content.removeAll();
	}

	@Override
	public void setEnabled(boolean enable) {
		super.setEnabled(enable);
		content.setEnabled(enable);
	}

}
