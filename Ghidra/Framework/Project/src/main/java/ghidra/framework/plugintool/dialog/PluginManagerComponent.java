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
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.HyperlinkEvent.EventType;

import docking.EmptyBorderToggleButton;
import docking.widgets.HyperlinkComponent;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.*;
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

	private class PluginPackageComponent extends JPanel {
		private final Color BG = Color.white;
		private final PluginPackage pluginPackage;
		private final GCheckBox checkBox;
		
		PluginPackageComponent(PluginPackage pluginPackage) {
			super(new BorderLayout());
			setBackground(BG);

			this.pluginPackage = pluginPackage;
			this.checkBox = new GCheckBox();

			initizalizeCheckBoxSection();
			initializeLabelSection();
			initializeDescriptionSection();

			setBorder(BorderFactory.createLineBorder(Color.DARK_GRAY));
			updateCheckBoxState();
		}

		private void initizalizeCheckBoxSection() {
			final JPanel checkboxPanel = new JPanel(new HorizontalLayout(0));
			checkboxPanel.setBackground(BG);
			
			checkBox.addActionListener(e -> checkBoxClicked());
			if (!pluginPackage.isfullyAddable()) {
				checkBox.setEnabled(false);
			}
			checkBox.setBackground(BG);
			
			checkboxPanel.add(Box.createHorizontalStrut(10));
			checkboxPanel.add(checkBox);
			checkboxPanel.add(Box.createHorizontalStrut(10));
			
			final JLabel iconLabel =
				new GIconLabel(ResourceManager.getScaledIcon(pluginPackage.getIcon(), 32, 32, 32));
			iconLabel.setBackground(BG);
			
			checkboxPanel.add(iconLabel);
			checkboxPanel.add(Box.createHorizontalStrut(10));
			checkboxPanel.setPreferredSize(new Dimension(84, 70));
			
			add(checkboxPanel, BorderLayout.WEST);
		}
		
		private void initializeLabelSection() {
			final JPanel centerPanel = new JPanel(new GridBagLayout());
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.HORIZONTAL;
			gbc.weightx = 1.0;

			centerPanel.setBackground(BG);
			
			final JPanel labelPanel = new JPanel(new VerticalLayout(3));
			labelPanel.setBackground(BG);
			
			final GLabel nameLabel = new GLabel(pluginPackage.getName());
			nameLabel.setFont(nameLabel.getFont().deriveFont(18f));
			nameLabel.setForeground(Color.BLACK);
			labelPanel.add(nameLabel);
			
			final HyperlinkComponent configureHyperlink = createConfigureHyperlink();
			labelPanel.add(configureHyperlink);
			
			labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 25, 0, 40));
			centerPanel.add(labelPanel, gbc);
			add(centerPanel);
		}
		
		private HyperlinkComponent createConfigureHyperlink() {
			final HyperlinkComponent configureHyperlink =
					new HyperlinkComponent("<html> <a href=\"Configure\">Configure</a>");
				configureHyperlink.addHyperlinkListener("Configure", e -> {
					if (e.getEventType() == EventType.ACTIVATED) {
						managePlugins(PluginPackageComponent.this.pluginPackage);
					}
				});
				configureHyperlink.setBackground(BG);
				return configureHyperlink;
		}
		
		private String enchanceDescription(final String text) {
			return String.format("<html><body style='width: 300px'>%s</body></html>", text);
		}
		
		private void initializeDescriptionSection() {
			final String htmlDescription = enchanceDescription(pluginPackage.getDescription());
			
			final JLabel descriptionlabel = new GHtmlLabel(htmlDescription);
			descriptionlabel.setForeground(Color.GRAY);
			descriptionlabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
			descriptionlabel.setVerticalAlignment(SwingConstants.TOP);
			descriptionlabel.setToolTipText(
				HTMLUtilities.toWrappedHTML(pluginPackage.getDescription(), 80));
			
			add(descriptionlabel, BorderLayout.EAST);
		}

		protected void checkBoxClicked() {
			boolean isSelected = checkBox.isSelected();
			if (isSelected) {
				model.addAllPlugins(pluginPackage);
			}
			else {
				model.removeAllPlugins(pluginPackage);
			}

		}

		void updateCheckBoxState() {
			checkBox.setSelected(
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
