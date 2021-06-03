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

import javax.swing.ImageIcon;

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

public class DisplayAsXMLAction extends DisplayAsAction {

	protected ConsoleService consoleService;
	protected ImageIcon ICON_XML = ResourceManager.loadImage("images/text-xml.png");;

	public DisplayAsXMLAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("DisplayXml", tool, owner, provider);
		String[] path = new String[] { "Display as...", "XML" };
		setPopupMenuData(new MenuData(path, ICON_XML));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_E, InputEvent.CTRL_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "display_as_xml"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container) {
		consoleService = provider.getConsoleService();
		if (consoleService == null) {
			Msg.showError(this, tool.getToolFrame(), "DisplayAsXML Error",
				"ConsoleService not found: Please add a console service provider to your tool");
			return;
		}
		writeXml(container);
	}

	public void writeXml(ObjectContainer container) {
		Element root = container.toXml();
		XmlUtilities.setStringAttr(root, "Path", container.getTargetObject().getJoinedPath("."));
		//Document doc = new Document(root);
		//XmlUtilities.writePrettyDocToFile(doc, destFile);
		consoleService.println(XmlUtilities.toString(root));
	}

}
