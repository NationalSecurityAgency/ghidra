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
package ghidra.framework.plugintool.dialog;

import java.awt.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.HyperlinkEvent.EventType;

import docking.EmptyBorderToggleButton;
import docking.widgets.HyperlinkComponent;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginPackage;
import ghidra.framework.plugintool.util.PluginPackageState;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

public class PluginManagerComponent extends JPanel implements ChangeListener, Scrollable {
	private final PluginTool tool;
	private PluginConfigurationModel model;
	private List<PluginPackageComponent> packageComponentList = new ArrayList<>();

	PluginManagerComponent(PluginTool tool) {
		super(new VerticalLayout(2));
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		setBackground(Color.WHITE);
		this.tool = tool;
		model = new PluginConfigurationModel(tool, this);
		List<PluginPackage> pluginPackages = model.getPluginPackages();
		for (PluginPackage pluginPackage : pluginPackages) {
			PluginPackageComponent comp = new PluginPackageComponent(pluginPackage);
			packageComponentList.add(comp);
			add(comp);
		}
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		for (PluginPackageComponent comp : packageComponentList) {
			comp.updateCheckBoxState();
		}
	}

	void managePlugins(PluginPackage pluginPackage) {
		PluginInstallerDialog pluginInstallerDialog =
			new PluginInstallerDialog("Configure " + pluginPackage.getName() + " Plugins", tool,
				model.getPluginDescriptions(pluginPackage));
		tool.showDialog(pluginInstallerDialog);
	}

	void manageAllPlugins() {
		PluginInstallerDialog pluginTableDialog = new PluginInstallerDialog("Configure All Plugins",
			tool, model.getAllPluginDescriptions());
		tool.showDialog(pluginTableDialog);
	}

	class PluginPackageComponent extends JPanel {
		private Color BG = Color.white;
		private final PluginPackage pluginPackage;
		private JCheckBox jCheckBox;

		PluginPackageComponent(PluginPackage pluginPackage) {
			super(new BorderLayout());
			setBackground(BG);
			this.pluginPackage = pluginPackage;
			JPanel panel = new JPanel(new HorizontalLayout(0));
			panel.setBackground(BG);
			jCheckBox = new JCheckBox();
			jCheckBox.addActionListener(e -> checkBoxClicked());
			if (!pluginPackage.isfullyAddable()) {
				jCheckBox.setEnabled(false);
			}
			panel.add(Box.createHorizontalStrut(10));
			jCheckBox.setBackground(BG);
			panel.add(jCheckBox);
			panel.add(Box.createHorizontalStrut(10));
			JLabel label =
				new JLabel(ResourceManager.getScaledIcon(pluginPackage.getIcon(), 32, 32, 32));
			label.setBackground(BG);
			panel.add(label);
			panel.add(Box.createHorizontalStrut(10));
			add(panel, BorderLayout.WEST);

			JPanel labelPanel = new JPanel(new VerticalLayout(3));
			labelPanel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
			labelPanel.setBackground(BG);
			label = new JLabel(pluginPackage.getName());
			//label.setVerticalAlignment(SwingConstants.TOP);
			label.setFont(label.getFont().deriveFont(18f));
			label.setForeground(Color.BLACK);
			labelPanel.add(label);
			HyperlinkComponent hyper =
				new HyperlinkComponent("<html> <a href=\"Configure\">Configure</a>");
			hyper.addHyperlinkListener("Configure", e -> {
				if (e.getEventType() == EventType.ACTIVATED) {
					managePlugins(PluginPackageComponent.this.pluginPackage);
				}
			});
			hyper.setBackground(BG);
			labelPanel.add(hyper);
			labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 40));

			add(labelPanel);
			String htmlDescription = getHTMLDescription();
			JLabel descriptionlabel = new JLabel(htmlDescription);
			descriptionlabel.setForeground(Color.GRAY);
			descriptionlabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
			descriptionlabel.setVerticalAlignment(SwingConstants.TOP);
			descriptionlabel.setPreferredSize(new Dimension(300, 60));
			descriptionlabel.setToolTipText(
				HTMLUtilities.toWrappedHTML(pluginPackage.getDescription(), 80));
			add(descriptionlabel, BorderLayout.EAST);
			setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED, Color.LIGHT_GRAY,
				Color.DARK_GRAY));
			updateCheckBoxState();
		}

		private String getHTMLDescription() {
			String description = pluginPackage.getDescription();
			return HTMLUtilities.toHTML(description);
		}

		protected void checkBoxClicked() {
			boolean isSelected = jCheckBox.isSelected();
			if (isSelected) {
				model.addAllPlugins(pluginPackage);
			}
			else {
				model.removeAllPlugins(pluginPackage);
			}

		}

		void updateCheckBoxState() {
			jCheckBox.setSelected(
				model.getPackageState(pluginPackage) != PluginPackageState.NO_PLUGINS_LOADED);
		}
	}

	static class MyToggleButton extends EmptyBorderToggleButton {
		public MyToggleButton(Icon icon) {
			super(icon);
		}

		@Override
		public void setIcon(Icon newIcon) {
			Icon scaledIcon = ResourceManager.getScaledIcon(newIcon, 32, 32, 32);
			doSetIcon(scaledIcon);
		}
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return getPreferredSize();
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 50;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true;
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return 20;
	}
}
