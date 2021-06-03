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

import java.awt.Color;
import java.awt.Point;
import java.util.*;

import javax.swing.KeyStroke;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;

import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.actions.KeyBindingUtils;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HTMLUtilities;

/**
 * Panel that contains a JTextPane to show plugin description information.
 */
class PluginDetailsPanel extends AbstractDetailsPanel {

	private SimpleAttributeSet nameAttrSet;
	private SimpleAttributeSet depNameAttrSet;
	private SimpleAttributeSet descrAttrSet;
	private SimpleAttributeSet categoriesAttrSet;
	private SimpleAttributeSet classAttrSet;
	private SimpleAttributeSet locAttrSet;
	private SimpleAttributeSet developerAttrSet;
	private SimpleAttributeSet dependencyAttrSet;
	private SimpleAttributeSet noValueAttrSet;

	private final PluginConfigurationModel model;

	PluginDetailsPanel(PluginConfigurationModel model) {
		super();
		this.model = model;
		createFieldAttributes();
		createMainPanel();
	}

	void setPluginDescription(PluginDescription descriptor) {

		textLabel.setText("");
		if (descriptor == null) {
			return;
		}

		List<PluginDescription> dependencies = model.getDependencies(descriptor);
		Collections.sort(dependencies, (pd1, pd2) -> pd1.getName().compareTo(pd2.getName()));

		StringBuilder buffer = new StringBuilder("<HTML>");

		buffer.append("<TABLE cellpadding=2>");

		insertRowTitle(buffer, "Name");
		insertRowValue(buffer, descriptor.getName(),
			!dependencies.isEmpty() ? depNameAttrSet : nameAttrSet);

		insertRowTitle(buffer, "Description");
		insertRowValue(buffer, descriptor.getDescription(), descrAttrSet);

		insertRowTitle(buffer, "Status");
		insertRowValue(buffer, descriptor.getStatus().getDescription(),
			(descriptor.getStatus() == PluginStatus.RELEASED) ? titleAttrSet : developerAttrSet);

		insertRowTitle(buffer, "Package");
		insertRowValue(buffer, descriptor.getPluginPackage().getName(), categoriesAttrSet);

		insertRowTitle(buffer, "Category");
		insertRowValue(buffer, descriptor.getCategory(), categoriesAttrSet);

		insertRowTitle(buffer, "Plugin Class");
		insertRowValue(buffer, descriptor.getPluginClass().getName(), classAttrSet);

		insertRowTitle(buffer, "Class Location");
		insertRowValue(buffer, descriptor.getSourceLocation(), locAttrSet);

		insertRowTitle(buffer, "Used By");

		buffer.append("<TD VALIGN=\"TOP\">");

		if (dependencies.isEmpty()) {
			insertHTMLLine(buffer, "None", noValueAttrSet);
		}
		else {
			for (int i = 0; i < dependencies.size(); i++) {
				insertHTMLString(buffer, dependencies.get(i).getPluginClass().getName(),
					dependencyAttrSet);
				if (i < dependencies.size() - 1) {
					buffer.append(HTMLUtilities.BR);
				}
			}
			insertHTMLLine(buffer, "", titleAttrSet);  // add a newline
		}
		buffer.append("</TD>");
		buffer.append("</TR>");

		insertRowTitle(buffer, "Services Required");

		buffer.append("<TD VALIGN=\"TOP\">");

		List<Class<?>> servicesRequired = descriptor.getServicesRequired();
		if (servicesRequired.isEmpty()) {
			insertHTMLLine(buffer, "None", noValueAttrSet);
		}
		else {
			for (int i = 0; i < servicesRequired.size(); i++) {
				insertHTMLString(buffer, servicesRequired.get(i).getName(), dependencyAttrSet);
				if (i < servicesRequired.size() - 1) {
					buffer.append(HTMLUtilities.BR);
				}
			}
			insertHTMLLine(buffer, "", titleAttrSet);  // add a newline
		}
		buffer.append("</TD>");
		buffer.append("</TR>");

		//
		// Developer
		//
		//
		// Optional: Actions loaded by this plugin
		//
		addLoadedActionsContent(buffer, descriptor);

		buffer.append("</TABLE>");

		textLabel.setText(buffer.toString());
		sp.getViewport().setViewPosition(new Point(0, 0));
	}

	// creates an HTML table to display actions loaded by the plugin
	private void addLoadedActionsContent(StringBuilder buffer,
			PluginDescription pluginDescription) {
		if (!model.isLoaded(pluginDescription)) {
			return;
		}

		buffer.append("<TR>");
		buffer.append("<TD VALIGN=\"TOP\">");
		insertHTMLLine(buffer, "Loaded Actions:", titleAttrSet);
		buffer.append("</TD>");

		Set<DockingActionIf> actions = model.getActionsForPlugin(pluginDescription);
		if (actions.size() == 0) {
			buffer.append("<TD VALIGN=\"TOP\">");
			insertHTMLLine(buffer, "No actions for plugin", noValueAttrSet);
			buffer.append("</TD>");
			buffer.append("</TR>");
			return;
		}

		buffer.append("<TD VALIGN=\"TOP\">");

		buffer.append(
			"<TABLE BORDER=1><TR><TH>Action Name</TH><TH>Menu Path</TH><TH>Keybinding</TH></TR>");

		for (DockingActionIf dockableAction : actions) {
			buffer.append("<TR><TD WIDTH=\"200\">");
			insertHTMLString(buffer, dockableAction.getName(), locAttrSet);
			buffer.append("</TD>");

			buffer.append("<TD WIDTH=\"300\">");
			MenuData menuBarData = dockableAction.getMenuBarData();
			String[] menuPath = menuBarData == null ? null : menuBarData.getMenuPath();
			String menuPathString = createStringForMenuPath(menuPath);
			if (menuPathString != null) {
				insertHTMLString(buffer, menuPathString, locAttrSet);
			}
			else {
				MenuData popupMenuData = dockableAction.getPopupMenuData();
				String[] popupPath = popupMenuData == null ? null : popupMenuData.getMenuPath();

				if (popupPath != null) {
					insertHTMLString(buffer, "(in a context popup menu)", noValueAttrSet);
				}
				else {
					insertHTMLString(buffer, "Not in a menu", noValueAttrSet);
				}
			}

			buffer.append("</TD>");

			buffer.append("<TD WIDTH=\"100\">");
			KeyStroke keyBinding = dockableAction.getKeyBinding();
			if (keyBinding != null) {
				String keyStrokeString = KeyBindingUtils.parseKeyStroke(keyBinding);
				insertHTMLString(buffer, keyStrokeString, locAttrSet);
			}
			else {
				insertHTMLString(buffer, "No keybinding", noValueAttrSet);
			}

			buffer.append("</TD></TR>");
		}

		buffer.append("</TABLE>");
		buffer.append("</TD>");
		buffer.append("</TR>");
	}

	private String createStringForMenuPath(String[] path) {
		if (path == null) {
			return null;
		}

		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < path.length; i++) {
			buffy.append(path[i].replaceAll("\\&", ""));  // strip off the mnemonic identifier '&'
			if (i != path.length - 1) {
				buffy.append("->");
			}
		}
		return buffy.toString();
	}

	@Override
	protected void createFieldAttributes() {
		titleAttrSet = new SimpleAttributeSet();
		titleAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		titleAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		titleAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		titleAttrSet.addAttribute(StyleConstants.Foreground, new Color(140, 0, 0));

		nameAttrSet = new SimpleAttributeSet();
		nameAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		nameAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		nameAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		nameAttrSet.addAttribute(StyleConstants.Foreground, new Color(0, 204, 51));

		depNameAttrSet = new SimpleAttributeSet();
		depNameAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		depNameAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		depNameAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		depNameAttrSet.addAttribute(StyleConstants.Foreground, Color.RED);

		descrAttrSet = new SimpleAttributeSet();
		descrAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		descrAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		descrAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		descrAttrSet.addAttribute(StyleConstants.Foreground, Color.BLUE);

		categoriesAttrSet = new SimpleAttributeSet();
		categoriesAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		categoriesAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		categoriesAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		categoriesAttrSet.addAttribute(StyleConstants.Foreground, new Color(204, 0, 204));

		classAttrSet = new SimpleAttributeSet();
		classAttrSet.addAttribute(StyleConstants.FontFamily, "monospaced");
		classAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		classAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		classAttrSet.addAttribute(StyleConstants.Foreground, Color.BLACK);

		locAttrSet = new SimpleAttributeSet();
		locAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		locAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		locAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		locAttrSet.addAttribute(StyleConstants.Foreground, Color.DARK_GRAY);

		developerAttrSet = new SimpleAttributeSet();
		developerAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		developerAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		developerAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		developerAttrSet.addAttribute(StyleConstants.Foreground, new Color(230, 15, 85));

		dependencyAttrSet = new SimpleAttributeSet();
		dependencyAttrSet.addAttribute(StyleConstants.FontFamily, "monospaced");
		dependencyAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		dependencyAttrSet.addAttribute(StyleConstants.Bold, Boolean.TRUE);
		dependencyAttrSet.addAttribute(StyleConstants.Foreground, new Color(23, 100, 30));

		noValueAttrSet = new SimpleAttributeSet();
		noValueAttrSet.addAttribute(StyleConstants.FontFamily, "Tahoma");
		noValueAttrSet.addAttribute(StyleConstants.FontSize, Integer.valueOf(11));
		noValueAttrSet.addAttribute(StyleConstants.Italic, Boolean.TRUE);
		noValueAttrSet.addAttribute(StyleConstants.Foreground, new Color(192, 192, 192));
	}
}
