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
package ghidra.plugins.fsbrowser;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.widgets.tree.GTreeNode;
import ghidra.app.services.ProgramManager;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

/**
 * {@link FileSystemBrowserPlugin} utility methods that other things might find useful.
 */
public class FSBUtils {

	public static FSRL getFileFSRLFromContext(ActionContext context) {
		return getFSRLFromContext(context, false);
	}

	public static FSRL getFSRLFromContext(ActionContext context, boolean dirsOk) {
		if (context == null || !(context.getContextObject() instanceof FSBNode)) {
			return null;
		}

		FSBNode node = (FSBNode) context.getContextObject();
		FSRL fsrl = node.getFSRL();
		if (!dirsOk && node instanceof FSBRootNode && fsrlHasContainer(fsrl.getFS())) {
			// 'convert' a file system root node back into its container file
			return fsrl.getFS().getContainer();
		}

		boolean isDir = (node instanceof FSBDirNode) || (node instanceof FSBRootNode);
		if (isDir && !dirsOk) {
			return null;
		}

		return fsrl;
	}

	public static boolean fsrlHasContainer(FSRLRoot fsFSRL) {
		return fsFSRL.hasContainer() && !fsFSRL.getProtocol().equals(LocalFileSystem.FSTYPE);
	}

	public static FSBRootNode getNodesRoot(FSBNode node) {
		GTreeNode tmp = node;
		while (tmp != null && !(tmp instanceof FSBRootNode)) {
			tmp = tmp.getParent();
		}
		return (tmp instanceof FSBRootNode) ? (FSBRootNode) tmp : null;
	}

	/**
	 * Returns the {@link ProgramManager} associated with this fs browser plugin.
	 * <p>
	 * When this FS Browser plugin is part of the front-end tool, this will search
	 * for an open CodeBrowser tool that can be used to handle programs.
	 * <p>
	 * When this FS Browser plugin is part of a CodeBrowser tool, this will just return
	 * the local ProgramManager / CodeBrowser.
	 *
	 * @param tool The plugin tool.
	 * @param allowUserPrompt boolean flag to allow this method to query the user to select
	 * a CodeBrowser.
	 * @return null if front-end and no open CodeBrowser, otherwise returns the local
	 * CodeBrowser ProgramManager service.
	 */
	public static ProgramManager getProgramManager(PluginTool tool, boolean allowUserPrompt) {
		PluginTool pmTool = null;
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			pmTool = tool;
		}
		else {
			List<PluginTool> runningPMTools = FSBUtils.getRunningProgramManagerTools(tool);
			if (runningPMTools.size() == 1) {
				pmTool = runningPMTools.get(0);
			}
			else {
				pmTool = allowUserPrompt ? selectPMTool(tool) : null;
			}
		}
		return (pmTool != null) ? pmTool.getService(ProgramManager.class) : null;
	}

	public static List<PluginTool> getRunningProgramManagerTools(PluginTool tool) {
		List<PluginTool> pluginTools = new ArrayList<>();
		for (PluginTool runningTool : tool.getToolServices().getRunningTools()) {
			PluginTool pt = runningTool;
			ProgramManager pmService = pt.getService(ProgramManager.class);
			if (pmService != null) {
				pluginTools.add(pt);
			}
		}
		return pluginTools;
	}

	private static PluginTool selectPMTool(PluginTool tool) {
		ProgramManager pm = tool.getService(ProgramManager.class);
		if (pm != null) {
			return tool;
		}

		List<PluginTool> pluginTools = FSBUtils.getRunningProgramManagerTools(tool);

		if (pluginTools.size() == 1) {
			return pluginTools.get(0);
		}

		if (pluginTools.isEmpty()) {
			Msg.showWarn(tool, tool.getActiveWindow(), "No open tools",
				"There are no open tools to use to open a program with");
			return null;
		}

		PluginTool pt = SelectFromListDialog.selectFromList(pluginTools, "Select tool",
			"Select a tool to use to open programs", pluginTool -> pluginTool.getName());
		return pt;
	}

}
