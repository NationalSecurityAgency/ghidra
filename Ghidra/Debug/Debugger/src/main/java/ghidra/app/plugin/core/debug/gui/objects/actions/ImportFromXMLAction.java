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
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;

import org.jdom.Attribute;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.gui.objects.components.DummyTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

public class ImportFromXMLAction extends ImportExportAsAction {

	protected ImageIcon ICON_XML = ResourceManager.loadImage("images/text-xml.png");

	public ImportFromXMLAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("ImportFromXML", tool, owner, provider);
		fileExt = ".xml";
		fileMode = GhidraFileChooserMode.FILES_ONLY;
		setMenuBarData(new MenuData(new String[] { IMPORT, "from XML" }, ICON_XML, GROUP));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_E, InputEvent.ALT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "import_from_xml"));
		provider.addLocalAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	protected void doAction(ObjectContainer container, File f) {
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				InputStream is = null;
				try {

					ObjectContainer cp = new ObjectContainer(null, null);
					DebuggerObjectsProvider p = new DebuggerObjectsProvider(provider.getPlugin(),
						provider.getModel(), cp, true);
					cp.propagateProvider(p);
					p.update(cp);

					is = new FileInputStream(f);
					SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
					Element root = sax.build(is).getRootElement();

					List<String> path = new ArrayList<>();
					Attribute pathStr = root.getAttribute("Path");
					for (String s : pathStr.getValue().split("\\.")) {
						path.add(s);
					}
					DummyTargetObject to = xmlToObject(p, root, path);
					ObjectContainer c = p.getRoot();
					c.setTargetObject(to);
					provider.update(c);
				}
				catch (Exception e) {
					Msg.showError(this, provider.getComponent(), "Load Failed", e.getMessage());
				}
				finally {
					try {
						is.close();
					}
					catch (IOException e) {
						// we tried
					}
				}
			}
		});
	}

	private DummyTargetObject xmlToObject(DebuggerObjectsProvider p, Element e, List<String> path) {
		String key = convertName(e.getName());
		Attribute type = e.getAttribute("Type");
		Attribute value = e.getAttribute("Value");
		List<TargetObject> objects = new ArrayList<>();
		for (Object c : e.getChildren()) {
			if (c instanceof Element) {
				Element ce = (Element) c;
				List<String> npath = new ArrayList<>();
				npath.addAll(path);
				npath.add(convertName(ce.getName()));
				TargetObject to = xmlToObject(p, ce, npath);
				objects.add(to);
			}
		}
		String tstr = (type != null) ? type.getValue() : "";
		String vstr = (value != null) ? value.getValue() : "";
		//return new DummyTargetObject(p.getRoot().getTargetObject().getClient(), path, tstr, vstr, "");
		return new DummyTargetObject(key, path, tstr, vstr, "", objects);
	}

	private String convertName(String name) {
		return name.contains("_0x") ? "[" + name.substring(name.indexOf("_") + 1) + "]" : name;
	}

}
