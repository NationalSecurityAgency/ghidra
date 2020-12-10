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
package ghidra.app.plugin.core.debug.gui.objects.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Element;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

public class DisplayFilteredXMLAction extends DisplayFilteredAction {

	protected ConsoleService consoleService;
	protected ImageIcon ICON_XML = ResourceManager.loadImage("images/text-xml.png");;

	public DisplayFilteredXMLAction(PluginTool tool, String owner,
			DebuggerObjectsProvider provider) {
		super("DisplayFilteredXML", tool, owner, provider);
		String[] path = new String[] { "Display filtered...", "XML" };
		setPopupMenuData(new MenuData(path, ICON_XML));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_E,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "display_filtered_xml"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container, List<String> path) {
		consoleService = provider.getConsoleService();
		if (consoleService == null) {
			Msg.showError(this, tool.getToolFrame(), "DisplayFilteredGraph Error",
				"ConsoleService not found: Please add a console service provider to your tool");
			return;
		}
		ObjectContainer clone = ObjectContainer.clone(container);
		clone.setImmutable(true);
		getOffspring(clone, path);
	}

	@Override
	protected void finishGetOffspring(ObjectContainer container, final List<String> path) {
		writeXml(container, path);
	}

	public void writeXml(ObjectContainer container, final List<String> path) {
		Element root = container.toXml();
		String joinedPath = StringUtils.join(path, ".");
		XmlUtilities.setStringAttr(root, "Path", joinedPath);
		consoleService.println(XmlUtilities.toString(root));
	}

}
