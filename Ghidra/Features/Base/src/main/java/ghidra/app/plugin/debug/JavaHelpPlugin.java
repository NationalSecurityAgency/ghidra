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
package ghidra.app.plugin.debug;

import java.awt.*;
import java.io.*;
import java.util.*;
import java.util.List;

import javax.swing.JButton;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.actions.SharedStubKeyBindingAction;
import docking.help.*;
import docking.tool.ToolConstants;
import ghidra.app.DeveloperPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.*;

/**
 * Generate a file of all components and actions in the 
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = DeveloperPluginPackage.NAME,
	category = PluginCategoryNames.TESTING,
	shortDescription = "Write JavaHelp Info",
	description = "This plugin identifies " +
			"those plugin actions that do not have help associated with them. The file, " +
			JavaHelpPlugin.infoName + ", is written to your home directory."
)
//@formatter:on
public class JavaHelpPlugin extends Plugin implements FrontEndable {

	static final String infoName = "GhidraHelpInfo.txt";

	private static final Set<String> noHelpActions = new HashSet<>();
	static {
		noHelpActions.add("DockingWindows - Help");
		noHelpActions.add("DockingWindows - HelpInfo");
		noHelpActions.add("DockingWindows - Set KeyBinding");
		noHelpActions.add("Tool - Contents");
		noHelpActions.add("Tool - Release Notes");
		noHelpActions.add("TipOfTheDayPlugin - Tips of the day");
		noHelpActions.add("MemoryUsagePlugin - Show VM memory");
		noHelpActions.add("Tool - Show Log");
		noHelpActions.add("GhidraScriptMgrPlugin - Ghidra API Help");
	}

	public JavaHelpPlugin(PluginTool tool) {
		super(tool);

		DockingAction action = new DockingAction("Generate Help Info File", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				TaskLauncher.launch(new WriterTask());
			}
		};

		DockingWindowManager.getHelpService().excludeFromHelp(action);
		action.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_TOOLS, "Write Help Info File" }));
		tool.addAction(action);
	}

	private class WriterTask extends Task {

		WriterTask() {
			super("Finding Actions Without Help", true, true, true, true);
		}

		@Override
		public void run(TaskMonitor monitor) {
			writeHelpInfo(monitor);
		}
	}

	private void writeHelpInfo(TaskMonitor monitor) {
		Project project = tool.getProject();
		if (project == null) {
			Msg.showWarn(this, null, "Cannot Generate Help Report",
				"You must have a project open to generate help information.");
			return;
		}

		HelpService help = Help.getHelpService();
		if (help == null || !(help instanceof HelpManager)) {
			Msg.showError(this, null, "Cannot Generate Help Report",
				"HelpManager failed to initialize properly");
			return;
		}

		HelpManager hm = (HelpManager) help;
		String filename = System.getProperty("user.home") + File.separator + infoName;
		File file = new File(filename);

		if (file.exists()) {
			file.delete();
		}

		PrintWriter out = null;
		try {
			out = new PrintWriter(new FileOutputStream(file));
			Map<Object, HelpLocation> map = hm.getInvalidHelpLocations(monitor);

			// Filter
			monitor.initialize(map.size());
			monitor.setMessage("Filtering help items...");
			Iterator<Object> iter = map.keySet().iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				Object helpObj = iter.next();
				if (helpObj instanceof DockingAction) {
					DockingAction action = (DockingAction) helpObj;
					if (shouldSkipHelpCheck(action)) {
						iter.remove();
					}
				}
				monitor.initialize(1);
			}

			out.println("Unresolved Help Locations: " + map.size());
			List<HelpInfoObject> helpInfos = new ArrayList<>(map.size());

			monitor.initialize(map.size());
			monitor.setMessage("Procesing actions...");
			iter = map.keySet().iterator();
			int i = 1;
			while (iter.hasNext()) {
				monitor.checkCanceled();
				Object helpObj = iter.next();
				HelpLocation helpLoc = map.get(helpObj);
				HelpInfoObject helpInfoObject = new HelpInfoObject(helpObj, helpLoc);
				if (!helpInfos.contains(helpInfoObject)) {
					helpInfos.add(helpInfoObject);
				}
				monitor.initialize(1);
			}

			if (helpInfos.size() == 0) {
				Msg.showInfo(this, tool.getToolFrame(), "Help Validation Complete",
					"No items missing help were found");
				return;
			}

			Collections.sort(helpInfos);

			monitor.setMessage("Writing items missing help...");
			for (HelpInfoObject helpInfo : helpInfos) {
				monitor.checkCanceled();
				writeHelpInfo(out, helpInfo, i++);
				monitor.initialize(1);
			}

			out.flush();
			Msg.showInfo(this, tool.getToolFrame(), "Help Info File Write Completed",
				"Unresolved Help Locations: " + map.size() + "\nHelp info file written to\n" +
					filename);
		}
		catch (Exception e) {
			Msg.showError(this, null, "Error", "Error writing JavaHelp info", e);
		}
		finally {
			if (out != null) {
				out.close();
			}
		}
	}

	private boolean shouldSkipHelpCheck(DockingAction action) {
		String actionName = action.getOwner() + " - " + action.getName();
		if (action instanceof SharedStubKeyBindingAction) {
			return true;
		}
		if (noHelpActions.contains(actionName)) {
			return true;
		}
		if (isKeybindingOnly(action)) {
			return true;
		}
		return false;
	}

	private boolean isKeybindingOnly(DockingAction action) {
		if (action.getToolBarData() != null) {
			return false;
		}
		if (action.getMenuBarData() != null) {
			return false;
		}
		if (action.getPopupMenuData() != null) {
			return false;
		}
		return true;
	}

	private void writeHelpInfo(PrintWriter out, HelpInfoObject helpInfo, int num) {

		Object helpObj = helpInfo.helpObject;
		HelpLocation helpLoc = helpInfo.location;

		out.println();
		out.println(num + "). HELP OBJECT: " + helpObj.getClass().getName());
		if (helpObj instanceof DockingAction) {
			DockingAction action = (DockingAction) helpObj;
			out.println("     ACTION: " + action.getOwner() + " - " + action.getName());
			out.println("     INCEPTION:" + action.getInceptionInformation());
		}
		else if (helpObj instanceof DockingDialog) {
			DockingDialog dlg = (DockingDialog) helpObj;
			out.println("     DIALOG TITLE: " + dlg.getTitle());
		}
		else if (helpObj instanceof ComponentProvider) {
			ComponentProvider provider = (ComponentProvider) helpObj;
			out.println("     PROVIDER: " + provider.getName());
		}
		else if (helpObj instanceof JButton) {
			JButton button = (JButton) helpObj;
			out.println("     BUTTON: " + button.getText());
			Component c = button;
			while (c != null && !(c instanceof Window)) {
				c = c.getParent();
			}
			if (c instanceof Dialog) {
				out.println("     DIALOG: " + ((Dialog) c).getTitle());
			}
			if (c instanceof Frame) {
				out.println("     FRAME: " + ((Frame) c).getTitle());
			}
		}
		out.println("     HELP-LOCATION: " + helpLoc);
	}

	private class HelpInfoObject implements Comparable<HelpInfoObject> {

		private Object helpObject;
		private HelpLocation location;

		HelpInfoObject(Object object, HelpLocation location) {
			this.helpObject = object;
			this.location = location;
		}

		@Override
		public int compareTo(HelpInfoObject o) {
			if (helpObject instanceof DockingAction) {
				if (!(o.helpObject instanceof DockingAction)) {
					return -1; // put DockingAction object before other types
				}

				DockingAction action = (DockingAction) helpObject;
				String myInceptionInfo = action.getInceptionInformation();
				DockingAction otherDockingAction = (DockingAction) o.helpObject;
				String otherInceptionInfo = otherDockingAction.getInceptionInformation();
				return myInceptionInfo.compareTo(otherInceptionInfo);
			}

			String myClassName = helpObject.getClass().getName();
			String otherClassName = o.helpObject.getClass().getName();
			return myClassName.compareTo(otherClassName);
		}

		@Override
		public String toString() {
			return location + " for " + helpObject;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((helpObject == null) ? 0 : helpObject.hashCode());
			result = prime * result + ((location == null) ? 0 : location.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			HelpInfoObject other = (HelpInfoObject) obj;
			if (helpObject == null) {
				if (other.helpObject != null) {
					return false;
				}
			}
			else if (!helpObject.equals(other.helpObject)) {
				return false;
			}
			if (location == null) {
				if (other.location != null) {
					return false;
				}
			}
			else if (!location.equals(other.location)) {
				return false;
			}
			return true;
		}
	}

}
