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
import java.util.*;

import javax.swing.ImageIcon;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.app.plugin.core.debug.gui.objects.components.DummyTargetObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

public class ImportFromFactsAction extends ImportExportAsAction {

	protected ImageIcon ICON_FACTS = ResourceManager.loadImage("images/closedFolder.png");
	private Map<String, Map<String, String>> maps =
		new LinkedHashMap<String, Map<String, String>>();

	public ImportFromFactsAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("ImportFromFacts", tool, owner, provider);
		fileExt = "";
		fileMode = GhidraFileChooserMode.DIRECTORIES_ONLY;
		setMenuBarData(new MenuData(new String[] { IMPORT, "from facts" }, ICON_FACTS, GROUP));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, InputEvent.ALT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "import_from_facts"));
		provider.addLocalAction(this);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	protected void doAction(ObjectContainer container, File dir) {
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				try {
					ObjectContainer cp = new ObjectContainer(null, null);
					DebuggerObjectsProvider p = new DebuggerObjectsProvider(provider.getPlugin(),
						provider.getModel(), cp, true);
					cp.propagateProvider(p);
					p.update(cp);

					if (!dir.isDirectory()) {
						return;
					}
					for (File f : dir.listFiles()) {
						BufferedReader reader =
							new BufferedReader(new InputStreamReader(new FileInputStream(f)));
						Map<String, String> map = new LinkedHashMap<String, String>();
						String name = f.getName();
						name = name.substring(0, name.indexOf(ExportAsFactsAction.fileExt2));
						maps.put(name, map);
						String line;
						while (null != (line = reader.readLine())) {
							String[] split = line.split(ExportAsFactsAction.SEP);
							if (split.length == 2) {
								map.put(split[0], split[1]);
							}
							else {
								map.put(split[0], "");
							}
						}
						reader.close();
					}

					Map<String, DummyTargetObject> objMap = new LinkedHashMap<>();
					Map<String, String> map = maps.get("ObjectPath");
					for (String key : map.keySet()) {
						String pathStr = map.get(key);
						String[] split = pathStr.split(ExportAsFactsAction.SPLIT);
						List<String> path = new ArrayList<>();
						for (String s : split) {
							path.add(s);
						}
						String name = maps.get("ObjectName").get(key);
						String value = maps.get("ObjectValue").get(key);
						String kind = maps.get("ObjectType").get(key);
						DummyTargetObject to =
							new DummyTargetObject(convertName(name), path, kind, value, "", null);
						objMap.put(key, to);
					}
					Map<String, String> cmap = maps.get("ObjectChildren");
					for (String key : cmap.keySet()) {
						String cid = cmap.get(key);
						String pkey = key.substring(0, key.indexOf(":"));
						DummyTargetObject to = objMap.get(pkey);
						DummyTargetObject cto = objMap.get(cid);
						to.addObject(cto);
						cto.setParent(to);
					}
					DummyTargetObject root = null;
					for (DummyTargetObject to : objMap.values()) {
						if (to.getParent() == null) {
							root = to;
							break;
						}
					}
					if (root != null) {
						ObjectContainer c = p.getRoot();
						c.setTargetObject(root);
						provider.update(c);
					}
				}
				catch (Exception e) {
					e.printStackTrace();
					Msg.showError(this, provider.getComponent(), "Load Failed", e);
				}
			}
		});
	}

	private String convertName(String name) {
		return name.contains("_0x") ? "[" + name.substring(name.indexOf("_") + 1) + "]" : name;
	}

}
