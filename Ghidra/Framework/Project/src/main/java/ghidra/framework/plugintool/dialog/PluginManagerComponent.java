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

import javax.accessibility.AccessibleContext;
import javax.swing.*;

import docking.widgets.GHyperlinkComponent;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.*;
import generic.theme.*;
import generic.theme.GThemeDefaults.Colors;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.HorizontalLayout;
import ghidra.util.layout.VerticalLayout;
import resources.ResourceManager;

public class PluginManagerComponent extends JPanel implements Scrollable {
	private static final Icon DEFAULT_ICON = new GIcon("icon.plugin.manager.default");

	private final PluginTool tool;
	private PluginConfigurationModel model;
	private List<PluginPackagePanel> packageComponentList = new ArrayList<>();

	PluginManagerComponent(PluginTool tool, PluginConfigurationModel model) {
		super(new VerticalLayout(2));
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		setBackground(new GColor("color.bg"));
		this.tool = tool;
		this.model = model;
		model.setChangeCallback(this::updateCheckboxes);

		List<PluginPackage> pluginPackages = model.getPluginPackages();
		for (PluginPackage pluginPackage : pluginPackages) {
			PluginPackagePanel panel = new PluginPackagePanel(pluginPackage);
			packageComponentList.add(panel);
			add(panel);
		}

		ExtensionsPanel extensionsPanel = new ExtensionsPanel();
		add(extensionsPanel);
	}

	private void updateCheckboxes() {
		for (PluginPackagePanel comp : packageComponentList) {
			comp.updateCheckBoxState();
		}
	}

	void managePlugins(PluginPackage pluginPackage) {
		List<PluginDescription> descriptons = model.getPluginDescriptions(pluginPackage);
		PluginInstallerDialog pluginInstallerDialog = new PluginInstallerDialog(
			"Configure " + pluginPackage.getName() + " Plugins", tool, model, descriptons);
		tool.showDialog(pluginInstallerDialog);
	}

	void manageAllPlugins() {
		PluginInstallerDialog pluginTableDialog = new PluginInstallerDialog("Configure All Plugins",
			tool, model, model.getAllPluginDescriptions());
		tool.showDialog(pluginTableDialog);
	}

	void manageExtensions() {
		List<PluginDescription> descriptons = model.getPluginDescriptionsForExtensions();
		PluginInstallerDialog pluginInstallerDialog = new PluginInstallerDialog(
			"Configure Extension Plugins", tool, model, descriptons);
		tool.showDialog(pluginInstallerDialog);
	}

	PluginConfigurationModel getModel() {
		return model;
	}

	int getPackageCount() {
		return packageComponentList.size();
	}

	int getPluginCount(PluginPackage pluginPackage) {
		return model.getPluginDescriptions(pluginPackage).size();
	}

	void selectPluginPackage(PluginPackage pluginPackage, boolean selected) {
		if (selected) {
			model.addSupportedPlugins(pluginPackage);
		}
		else {
			model.removeAllPlugins(pluginPackage);
		}

	}

	boolean isAddAllCheckBoxEnabled(PluginPackage pluginPackage) {
		for (PluginPackagePanel ppc : packageComponentList) {
			if (ppc.pluginPackage.equals(pluginPackage)) {
				return ppc.selectAllCheckBox.isEnabled();
			}
		}

		throw new AssertException("No checkbox found for " + pluginPackage);
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
//=================================================================================================
// Inner Classes
//=================================================================================================

	/** A panel that represents a group of plugins, typically all plugins in a PluginPackage */
	private abstract class GroupPanel extends JPanel {
		protected static final Color BG = new GColor("color.bg");
		protected GCheckBox selectAllCheckBox;

		GroupPanel() {
			super(new BorderLayout());
			setBackground(BG);
			setBorder(BorderFactory.createLineBorder(Colors.BORDER));
		}

		protected void build() {
			this.selectAllCheckBox = createCheckBox();

			initializeLabelSection();
			initializeDescriptionSection();

			setBorder(BorderFactory.createLineBorder(Colors.BORDER));
			updateCheckBoxState();
		}

		private void initializeLabelSection() {
			JPanel centerPanel = new JPanel(new GridBagLayout());
			GridBagConstraints gbc = new GridBagConstraints();
			gbc.fill = GridBagConstraints.HORIZONTAL;
			gbc.weightx = 1.0;

			centerPanel.setBackground(BG);

			JPanel labelPanel = new JPanel(new VerticalLayout(3));
			labelPanel.setBackground(BG);

			GLabel nameLabel = new GLabel(getGroupName());
			Gui.registerFont(nameLabel, "font.plugin.package.panel.name");
			nameLabel.setForeground(new GColor("color.fg.plugin.package.panel.name"));
			labelPanel.add(nameLabel);

			GHyperlinkComponent configureHyperlink = createConfigureHyperlink();
			labelPanel.add(configureHyperlink);

			labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 25, 0, 40));
			centerPanel.add(labelPanel, gbc);
			add(centerPanel);
		}

		protected abstract String getGroupName();

		protected abstract String getGroupDescription();

		protected abstract Icon getGroupIcon();

		protected abstract void addLink(GHyperlinkComponent link);

		protected abstract GCheckBox createCheckBox();

		protected abstract void updateCheckBoxState();

		private GHyperlinkComponent createConfigureHyperlink() {
			GHyperlinkComponent configureLink = new GHyperlinkComponent();
			addLink(configureLink);
			configureLink.setBackground(BG);
			return configureLink;
		}

		private String enchanceDescription(String text) {
			return String.format("<html><body style='width: 300px'>%s</body></html>", text);
		}

		private void initializeDescriptionSection() {
			String description = getGroupDescription();
			String htmlDescription = enchanceDescription(description);

			JLabel descriptionlabel = new GHtmlLabel(htmlDescription);
			descriptionlabel.setForeground(new GColor("color.fg.plugin.package.panel.description"));
			descriptionlabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
			descriptionlabel.setVerticalAlignment(SwingConstants.TOP);
			descriptionlabel.setToolTipText(HTMLUtilities.toWrappedHTML(description, 80));

			add(descriptionlabel, BorderLayout.EAST);
		}

	}


	private class ExtensionsPanel extends GroupPanel {

		private static final GIcon ICON = new GIcon("icon.plugin.manager.extensions");

		ExtensionsPanel() {
			build();
		}

		@Override
		protected String getGroupName() {
			return "Extensions";
		}

		@Override
		protected String getGroupDescription() {
			return "All plugins that belong to an Extension.";
		}

		@Override
		protected Icon getGroupIcon() {
			return ICON;
		}

		@Override
		protected void addLink(GHyperlinkComponent link) {
			link.addLink("Configure", "Configure Plugins", () -> {
				manageExtensions();
			});
		}

		@Override
		protected GCheckBox createCheckBox() {
			// not checkbox for this group; create a spacer for symmetry

			JPanel iconPanel = new JPanel(new HorizontalLayout(0));
			iconPanel.setBackground(BG);

			iconPanel.add(Box.createHorizontalStrut(40));

			Icon icon = getGroupIcon();
			JLabel iconLabel = new GIconLabel(ResourceManager.getScaledIcon(icon, 32, 32, 32));
			iconLabel.setBackground(BG);

			iconPanel.add(iconLabel);
			iconPanel.add(Box.createHorizontalStrut(10));
			iconPanel.setPreferredSize(new Dimension(84, 70));

			add(iconPanel, BorderLayout.WEST);

			return null;
		}

		@Override
		protected void updateCheckBoxState() {
			// no checkbox for this group
		}

	}

	private class PluginPackagePanel extends GroupPanel {

		private final PluginPackage pluginPackage;

		PluginPackagePanel(PluginPackage pluginPackage) {
			this.pluginPackage = pluginPackage;
			build();
		}

		@Override
		protected GCheckBox createCheckBox() {
			GCheckBox checkBox = new GCheckBox();
			AccessibleContext ac = checkBox.getAccessibleContext();
			ac.setAccessibleName(getGroupName() + " plugin package");
			ac.setAccessibleDescription(getGroupDescription());

			JPanel checkboxPanel = new JPanel(new HorizontalLayout(0));
			checkboxPanel.setBackground(BG);

			checkBox.addActionListener(
				e -> selectPluginPackage(pluginPackage, checkBox.isSelected()));
			if (model.hasOnlyUnstablePlugins(pluginPackage)) {
				checkBox.setEnabled(false);
			}
			checkBox.setBackground(BG);

			checkboxPanel.add(Box.createHorizontalStrut(10));
			checkboxPanel.add(checkBox);
			checkboxPanel.add(Box.createHorizontalStrut(10));

			Icon icon = getGroupIcon();
			if (icon == null) {
				icon = DEFAULT_ICON;
			}
			JLabel iconLabel = new GIconLabel(ResourceManager.getScaledIcon(icon, 32, 32, 32));
			iconLabel.setBackground(BG);

			checkboxPanel.add(iconLabel);
			checkboxPanel.add(Box.createHorizontalStrut(10));
			checkboxPanel.setPreferredSize(new Dimension(84, 70));

			add(checkboxPanel, BorderLayout.WEST);

			return checkBox;
		}

		@Override
		protected void updateCheckBoxState() {
			PluginPackageState state = model.getPackageState(pluginPackage);
			selectAllCheckBox.setSelected(state != PluginPackageState.NO_PLUGINS_LOADED);
		}

		@Override
		protected String getGroupName() {
			return pluginPackage.getName();
		}

		@Override
		protected Icon getGroupIcon() {
			return pluginPackage.getIcon();
		}

		@Override
		protected String getGroupDescription() {
			return pluginPackage.getDescription();
		}

		@Override
		protected void addLink(GHyperlinkComponent link) {
			link.addLink("Configure", "Configure Plugins", () -> {
				managePlugins(PluginPackagePanel.this.pluginPackage);
			});
		}


	}


}
