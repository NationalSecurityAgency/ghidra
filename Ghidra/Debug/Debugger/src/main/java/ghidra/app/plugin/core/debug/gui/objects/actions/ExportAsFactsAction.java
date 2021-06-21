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
import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.debug.gui.objects.DebuggerObjectsProvider;
import ghidra.app.plugin.core.debug.gui.objects.ObjectContainer;
import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class ExportAsFactsAction extends ImportExportAsAction {

	public static String SEP = "\t";
	public static String JOIN = ".";
	public static String SPLIT = "\\.";
	public static String fileExt2 = ".facts";
	protected ImageIcon ICON_FACTS = ResourceManager.loadImage("images/closedFolder.png");
	private Map<String, PrintWriter> files = new HashMap<String, PrintWriter>();

	public ExportAsFactsAction(PluginTool tool, String owner, DebuggerObjectsProvider provider) {
		super("ExportAsFacts", tool, owner, provider);
		fileExt = "";
		fileMode = GhidraFileChooserMode.DIRECTORIES_ONLY;
		String[] path = new String[] { "Export as...", "Facts" };
		setPopupMenuData(new MenuData(path, ICON_FACTS));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_F,
			InputEvent.SHIFT_DOWN_MASK));
		setHelpLocation(new HelpLocation(owner, "export_as_facts"));
		provider.addLocalAction(this);
	}

	@Override
	protected void doAction(ObjectContainer container, File dir) {
		if (container == null) {
			return;
		}
		writeFacts(container, dir);
		for (PrintWriter pw : files.values()) {
			pw.flush();
			pw.close();
		}
	}

	public String writeFacts(ObjectContainer container, File dir) {
		TargetObject to = container.getTargetObject();
		if (to == null) {
			return "";
		}
		String id = Integer.toHexString(to.getPath().hashCode());
		PrintWriter pw = getOrAddWriter(dir, "ObjectPath");
		pw.println(id + SEP + to.getJoinedPath(JOIN));
		pw = getOrAddWriter(dir, "ObjectName");
		pw.println(id + SEP + container.getPrefixedName());
		pw = getOrAddWriter(dir, "ObjectValue");
		pw.println(id + SEP + to.getDisplay());
		pw = getOrAddWriter(dir, "ObjectType");
		pw.println(id + SEP + to.getTypeHint());
		pw = getOrAddWriter(dir, "ObjectChildren");
		for (ObjectContainer c : container.getCurrentChildren()) {
			String cid = writeFacts(c, dir);
			pw.println(id + SEP + cid);
		}
		return id;
	}

	private PrintWriter getOrAddWriter(File dir, String name) {
		name += fileExt2;
		if (files.containsKey(name)) {
			return files.get(name);
		}
		File f = new File(dir, name);
		PrintWriter pw = null;
		try {
			pw = new PrintWriter(f);
			files.put(name, pw);
		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return pw;
	}

}
