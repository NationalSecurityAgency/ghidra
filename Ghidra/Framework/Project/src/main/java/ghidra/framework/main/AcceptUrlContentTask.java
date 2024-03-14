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
package ghidra.framework.main;

import java.io.IOException;
import java.net.URL;

import ghidra.framework.data.FolderLinkContentHandler;
import ghidra.framework.main.datatree.ProjectDataTreePanel;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.framework.protocol.ghidra.GhidraURLQueryTask;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class AcceptUrlContentTask extends GhidraURLQueryTask {

	private FrontEndPlugin plugin;

	public AcceptUrlContentTask(URL url, FrontEndPlugin plugin) {
		super("Accepting URL", url);
		this.plugin = plugin;
	}


	@Override
	public void processResult(DomainFile domainFile, URL url, TaskMonitor monitor)
			throws IOException {
		Swing.runNow(() -> {

			if (FolderLinkContentHandler.FOLDER_LINK_CONTENT_TYPE
					.equals(domainFile.getContentType())) {
				plugin.showLinkedFolder(domainFile);
				return;
			}
			AppInfo.getFrontEndTool().getToolServices().launchDefaultToolWithURL(url);
		});
	}

	@Override
	public void processResult(DomainFolder domainFolder, URL url, TaskMonitor monitor)
			throws IOException {
		ProjectDataPanel projectDataPanel = plugin.getProjectDataPanel();

		Swing.runNow(() -> {
			ProjectDataTreePanel dtp = projectDataPanel.openView(GhidraURL.getProjectURL(url));
			if (dtp == null) {
				return;
			}
			dtp.selectDomainFolder(domainFolder);
		});
	}

}
