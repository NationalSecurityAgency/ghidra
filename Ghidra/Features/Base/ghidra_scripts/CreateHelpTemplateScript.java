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
//Creates a template help file by reading all of the actions from a selected plugin.
//@category HELP

import java.io.*;
import java.util.*;

import docking.action.DockingActionIf;
import docking.actions.KeyBindingUtils;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.exception.CancelledException;

public class CreateHelpTemplateScript extends GhidraScript {

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		List<Plugin> plugins = getSortedPlugins(tool);
		Plugin selectedPlugin =
			askChoice("Select Plugin To Use To Generate Help", "Plugin", plugins, plugins.get(0));
		if (selectedPlugin == null) {
			printerr("no plugin selected, no help template created.");
			return;
		}
		File outputDirectory = askDirectory("Select Directory To Write Help File", "GO!");
		if (outputDirectory == null) {
			printerr("no output directory selected, no help template created.");
			return;
		}
		File outputFile = new File(outputDirectory, selectedPlugin.getName() + ".html");
		if (outputFile.exists()) {
			boolean keepExisting = askYesNo("Help File Already Exists",
				"The help file for " + selectedPlugin.getName() +
					" already exists.\nDo you want to keep the existing file?");
			if (keepExisting) {
				printerr("output help file already exists, user chose to keep existing.");
				return;
			}
		}
		writeHelpFile(tool, selectedPlugin, outputFile);
	}

	private void writeHelpFile(PluginTool tool, Plugin plugin, File outputFile)
			throws FileNotFoundException, CancelledException {
		PrintWriter printWriter = new PrintWriter(outputFile);
		try {
			printWriter.println(
				"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">");
			printWriter.println("<html>");
			printWriter.println("");
			printWriter.println("<head>");
			printWriter.println("\t" + "<title>" + plugin.getName() + "</title>");
			printWriter.println("\t" +
				"<link rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">");
			printWriter.println("</head>");
			printWriter.println("");
			printWriter.println("<body>");
			printWriter.println("");
			printWriter.println("<h1>" + plugin.getName() + "</h1>");
			printWriter.println("");
			printWriter.println("<h2>Introduction</h2>");
			printWriter.println("\t\t" + "<blockquote>");
			printWriter.println("");
			printWriter.println("\t\t" + "</blockquote>");
			printWriter.println("");
			printWriter.println("<h2>Actions</h2>");
			printWriter.println("");
			printWriter.println("<blockquote>");
			List<DockingActionIf> actions = getActions(tool, plugin);
			for (DockingActionIf action : actions) {
				monitor.checkCanceled();
				printWriter.println("\t" + "<h3><A name=\"" + action.getName().replace(' ', '_') +
					"\"></A>" + action.getName() + "</h3>");
				printWriter.println("\t\t" + "<blockquote>");
				printWriter.println("");
				printWriter.println("\t\t" + "</blockquote>");
			}
			printWriter.println("");
			printWriter.println("</blockquote>");
			printWriter.println("</body>");
			printWriter.println("</html>");
		}
		finally {
			printWriter.close();
		}
	}

	private List<DockingActionIf> getActions(PluginTool tool, Plugin plugin) {
		Set<DockingActionIf> actions = KeyBindingUtils.getKeyBindingActionsForOwner(tool, plugin.getName());
		List<DockingActionIf> list = new ArrayList<>(actions);
		Comparator<DockingActionIf> comparator = (action1, action2) -> {
			try {
				return action1.getName().compareTo(action2.getName());
			}
			catch (Exception e) {
				return 0;
			}
		};
		Collections.sort(list, comparator);
		return list;
	}

	private List<Plugin> getSortedPlugins(PluginTool tool) {
		List<Plugin> list = tool.getManagedPlugins();
		Comparator<Plugin> comparator = (plugin1, plugin2) -> {
			try {
				return plugin1.getName().compareTo(plugin2.getName());
			}
			catch (Exception e) {
				return 0;
			}
		};

		Collections.sort(list, comparator);
		return list;
	}

}
