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

import java.awt.Font;
import java.awt.Point;
import java.util.*;

import javax.swing.KeyStroke;

import docking.action.DockingActionIf;
import docking.action.MenuData;
import docking.actions.KeyBindingUtils;
import generic.theme.*;
import ghidra.framework.plugintool.PluginConfigurationModel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginDescription;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HTMLUtilities;

/**
 * Panel that contains a JTextPane to show plugin description information.
 */
class PluginDetailsPanel extends AbstractDetailsPanel {

	private static final GColor NO_VALUE_COLOR = new GColor("color.fg.pluginpanel.details.novalue");
	private static final GColor DEPENDENCY_COLOR =
		new GColor("color.fg.pluginpanel.details.dependency");
	private static final GColor LOCATION_COLOR = new GColor("color.fg.pluginpanel.details.loc");
	private static final GColor DEVELOPER_COLOR =
		new GColor("color.fg.pluginpanel.details.developer");
	private static final GColor CLASS_COLOR = new GColor("color.fg.pluginpanel.details.class");
	private static final GColor CATEGORIES_COLOR =
		new GColor("color.fg.pluginpanel.details.category");
	private static final GColor TITLE_COLOR = new GColor("color.fg.pluginpanel.details.title");
	private static final GColor DESCRIPTION_COLOR =
		new GColor("color.fg.pluginpanel.details.description");
	private static final GColor NAME_NO_DEPENDENTS_COLOR =
		new GColor("color.fg.pluginpanel.details.name.no.dependents");
	private static final GColor NAME_DEPENDENTS_COLOR =
		new GColor("color.fg.pluginpanel.details.name.has.dependents");

	private GAttributes nameAttrs;
	private GAttributes dependenciesNameAttrs;
	private GAttributes descriptionAttrs;
	private GAttributes categoriesAttrs;
	private GAttributes classAttrs;
	private GAttributes locationAttrs;
	private GAttributes developerAttrs;
	private GAttributes dependencyAttrs;
	private GAttributes noValueAttrs;

	private final PluginConfigurationModel model;
	private PluginTool tool;
	private PluginDescription currentDescriptor;

	PluginDetailsPanel(PluginTool tool, PluginConfigurationModel model) {
		this.tool = tool;
		this.model = model;
		createFieldAttributes();
		createMainPanel();
	}

	@Override
	protected void refresh() {
		setPluginDescription(currentDescriptor);
	}

	void setPluginDescription(PluginDescription descriptor) {

		this.currentDescriptor = descriptor;
		textLabel.setText("");
		if (descriptor == null) {
			return;
		}

		List<PluginDescription> dependencies = model.getDependencies(descriptor);
		Collections.sort(dependencies, (pd1, pd2) -> pd1.getName().compareTo(pd2.getName()));

		StringBuilder buffer = new StringBuilder("<html>");

		buffer.append("<TABLE cellpadding=2>");

		insertRowTitle(buffer, "Name");
		insertRowValue(buffer, descriptor.getName(),
			!dependencies.isEmpty() ? dependenciesNameAttrs : nameAttrs);

		insertRowTitle(buffer, "Description");
		insertRowValue(buffer, descriptor.getDescription(), descriptionAttrs);

		insertRowTitle(buffer, "Status");
		insertRowValue(buffer, descriptor.getStatus().getDescription(),
			(descriptor.getStatus() == PluginStatus.RELEASED) ? titleAttrs : developerAttrs);

		insertRowTitle(buffer, "Package");
		insertRowValue(buffer, descriptor.getPluginPackage().getName(), categoriesAttrs);

		insertRowTitle(buffer, "Category");
		insertRowValue(buffer, descriptor.getCategory(), categoriesAttrs);

		insertRowTitle(buffer, "Plugin Class");
		insertRowValue(buffer, descriptor.getPluginClass().getName(), classAttrs);

		insertRowTitle(buffer, "Class Location");
		insertRowValue(buffer, descriptor.getSourceLocation(), locationAttrs);

		insertRowTitle(buffer, "Used By");

		buffer.append("<TD VALIGN=\"TOP\">");

		if (dependencies.isEmpty()) {
			insertHTMLLine(buffer, "None", noValueAttrs);
		}
		else {
			for (int i = 0; i < dependencies.size(); i++) {
				insertHTMLString(buffer, dependencies.get(i).getPluginClass().getName(),
					dependencyAttrs);
				if (i < dependencies.size() - 1) {
					buffer.append(HTMLUtilities.BR);
				}
			}
			insertHTMLLine(buffer, "", titleAttrs);  // add a newline
		}
		buffer.append("</TD>");
		buffer.append("</TR>");

		insertRowTitle(buffer, "Services Required");

		buffer.append("<TD VALIGN=\"TOP\">");

		List<Class<?>> servicesRequired = descriptor.getServicesRequired();
		if (servicesRequired.isEmpty()) {
			insertHTMLLine(buffer, "None", noValueAttrs);
		}
		else {
			for (int i = 0; i < servicesRequired.size(); i++) {
				insertHTMLString(buffer, servicesRequired.get(i).getName(), dependencyAttrs);
				if (i < servicesRequired.size() - 1) {
					buffer.append(HTMLUtilities.BR);
				}
			}
			insertHTMLLine(buffer, "", titleAttrs);  // add a newline
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
		insertHTMLLine(buffer, "Loaded Actions:", titleAttrs);
		buffer.append("</TD>");

		Set<DockingActionIf> actions = Collections.emptySet();
		if (model.isLoaded(pluginDescription)) {
			actions =
				KeyBindingUtils.getKeyBindingActionsForOwner(tool, pluginDescription.getName());
		}

		if (actions.isEmpty()) {
			buffer.append("<TD VALIGN=\"TOP\">");
			insertHTMLLine(buffer, "No actions for plugin", noValueAttrs);
			buffer.append("</TD>");
			buffer.append("</TR>");
			return;
		}

		buffer.append("<TD VALIGN=\"TOP\">");

		buffer.append(
			"<TABLE BORDER=1><TR><TH>Action Name</TH><TH>Menu Path</TH><TH>Keybinding</TH></TR>");

		for (DockingActionIf dockableAction : actions) {
			buffer.append("<TR><TD WIDTH=\"200\">");
			insertHTMLString(buffer, dockableAction.getName(), locationAttrs);
			buffer.append("</TD>");

			buffer.append("<TD WIDTH=\"300\">");
			MenuData menuBarData = dockableAction.getMenuBarData();
			String[] menuPath = menuBarData == null ? null : menuBarData.getMenuPath();
			String menuPathString = createStringForMenuPath(menuPath);
			if (menuPathString != null) {
				insertHTMLString(buffer, menuPathString, locationAttrs);
			}
			else {
				MenuData popupMenuData = dockableAction.getPopupMenuData();
				String[] popupPath = popupMenuData == null ? null : popupMenuData.getMenuPath();

				if (popupPath != null) {
					insertHTMLString(buffer, "(in a context popup menu)", noValueAttrs);
				}
				else {
					insertHTMLString(buffer, "Not in a menu", noValueAttrs);
				}
			}

			buffer.append("</TD>");

			buffer.append("<TD WIDTH=\"100\">");
			KeyStroke keyBinding = dockableAction.getKeyBinding();
			if (keyBinding != null) {
				String keyStrokeString = KeyBindingUtils.parseKeyStroke(keyBinding);
				insertHTMLString(buffer, keyStrokeString, locationAttrs);
			}
			else {
				insertHTMLString(buffer, "No keybinding", noValueAttrs);
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

		Font font = Gui.getFont(FONT_DEFAULT);
		titleAttrs = new GAttributes(font, TITLE_COLOR);
		nameAttrs = new GAttributes(font, NAME_NO_DEPENDENTS_COLOR);
		dependenciesNameAttrs = new GAttributes(font, NAME_DEPENDENTS_COLOR);
		descriptionAttrs = new GAttributes(font, DESCRIPTION_COLOR);
		categoriesAttrs = new GAttributes(font, CATEGORIES_COLOR);
		locationAttrs = new GAttributes(font, LOCATION_COLOR);
		developerAttrs = new GAttributes(font, DEVELOPER_COLOR);

		Font fontMonospaced = Gui.getFont(FONT_MONOSPACED);
		classAttrs = new GAttributes(fontMonospaced, CLASS_COLOR);
		dependencyAttrs = new GAttributes(fontMonospaced, DEPENDENCY_COLOR);

		noValueAttrs = new GAttributes(font, NO_VALUE_COLOR);
	}
}
