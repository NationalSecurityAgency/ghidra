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
package ghidra.app.util.viewer.util;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

/**
 * Adds a border to a component that displays a title and provides a area for adding
 * components (usually icon buttons)
 */
public class TitledPanel extends JPanel {
	private JLabel title;
	private JPanel titlePanel;
	private JPanel iconPanel;
	private JComponent bottomComp;
	private List<JComponent> titleComps = new ArrayList<JComponent>();

	/**
	 * Creates a new TitlePanel
	 * @param name the name of the panel
	 * @param panel the component to wrap.
	 * @param margin the size of the margin to use.
	 */
	public TitledPanel(String name, JComponent panel, int margin) {
		super(new BorderLayout());
		titlePanel = new JPanel(new BorderLayout());
		iconPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 4, 1));
		iconPanel.setBorder(BorderFactory.createEmptyBorder(0,0,0,0));
		title = new JLabel(name);
		title.setToolTipText(name);
		JLabel filler = new JLabel();
		filler.setPreferredSize(new Dimension(margin, filler.getPreferredSize().height));
		titlePanel.add(filler, BorderLayout.WEST);

		titlePanel.setBorder(BorderFactory.createEmptyBorder(0,0, 0, 0)); 
		titlePanel.add(title, BorderLayout.CENTER);
		titlePanel.add(iconPanel, BorderLayout.EAST);
		
		add(titlePanel, BorderLayout.NORTH);
		add(panel, BorderLayout.CENTER);
	}
	public void setTitleName(String name) {
		title.setText(name);
		title.setToolTipText(name);
	}
	/**
	 * Adds a component to the right side of the title bar.
	 * @param comp the component to add.
	 */
	public void addTitleComponent(JComponent comp) {
		titleComps.add(0, comp);
		iconPanel.removeAll();
		for(int i=0;i<titleComps.size();i++) {
			iconPanel.add(titleComps.get(i));
		}
	}
	/**
	 * Sets a component below the main panel that was passed to the constructor.
	 * If the component passed to this method is null then the TitledPanel will
	 * not have a component below the main panel.
	 * @param comp the component to display below the main panel. Null indicates none.
	 */
	public void setBottomComponent(JComponent comp) {
		if (comp == bottomComp) {
			return;
		}
		if (bottomComp != null) {
			remove(bottomComp);
			bottomComp = null;
		}
		if (comp != null) {
			bottomComp = comp;
			add(bottomComp, BorderLayout.SOUTH);
		}
	}

}
