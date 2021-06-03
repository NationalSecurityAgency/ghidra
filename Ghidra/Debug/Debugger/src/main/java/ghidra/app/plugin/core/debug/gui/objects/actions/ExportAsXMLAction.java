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
import java.io.File;
import java.io.IOException;

import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;
import org.jdom.Document;
import org.jdom.Element;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

public class ExportAsXMLAction extends ImportExportAsAction {

	protected ImageIcon ICON_XML = ResourceManager.loadImage("images/text-xml.png");

	public ExportAsXMLAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("ExportAsXML", tool, owner, provider);
		fileExt = ".xml";
		fileMode = GhidraFileChooserMode.FILES_ONLY;
		String[] path = new String[] { "Export as...", "XML" };
		setPopupMenuData(new MenuData(path, ICON_XML));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_E,
			InputEvent.SHIFT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "export_as_xml"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container, File f) {
		writeXml(container, f);
	}

	public void writeXml(ObjectContainer container, File f) {
		if (container == null) {
			return;
		}
		Element root = container.toXml();
		String joinedPath = StringUtils.join(container.getTargetObject().getPath(), ".");
		XmlUtilities.setStringAttr(root, "Path", joinedPath);
		Document doc = new Document(root);
		try {
			XmlUtilities.writePrettyDocToFile(doc, f);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
	}

}
