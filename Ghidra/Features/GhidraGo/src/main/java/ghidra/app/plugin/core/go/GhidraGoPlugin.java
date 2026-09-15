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
package ghidra.app.plugin.core.go;

import java.io.IOException;
import java.net.URL;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.go.ipc.GhidraGoListener;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.Swing;

//@formatter:off
@PluginInfo(
	category = PluginCategoryNames.COMMON,
	status = PluginStatus.UNSTABLE,
	packageName = CorePluginPackage.NAME,
	shortDescription = "Listens for new GhidraURL's to launch using FrontEndTool's" +
		" accept method",
	description = "Polls the ghidraGo directory for any URL files written by the " +
		"GhidraGoSender and processes them in Ghidra",
	eventsConsumed = {ProjectPluginEvent.class})
//@formatter:on
/**
 * Polls the ghidraGo directory located in the user's temporary directory for any url files written
 * by the {@link GhidraGoSender} and processes them in Ghidra.
 */
public class GhidraGoPlugin extends Plugin implements ApplicationLevelOnlyPlugin {
	private GhidraGoListener listener;

	public GhidraGoPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void dispose() {
		projectClosed();
		super.dispose();
	}

	private void processUrl(URL url) {
		
		URL projectUrl = GhidraURL.getProjectURL(url);
		Msg.info(this, "GhidraGo accepting the resource at " + projectUrl);
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();

		// Check for case where server access has already been blocked to 
		// launching tool and then failing to access program. 
		if (!ClientUtil.getAllowListProvider().isAllowed(url)) {
			Msg.showError(this, frontEndTool.getActiveWindow(), "URL Access Not Allowed",
				"Access denied by Server Allow List:\n" + projectUrl);
			return;
		}
		
		Swing.runLater(() -> {
			frontEndTool.toFront();
			frontEndTool.accept(url);
		});
	}

	private void projectOpened() {
		projectClosed();
		try {
			listener = new GhidraGoListener((url) -> processUrl(url));
		}
		catch (IOException e) {
			Msg.showError(this, null, "GhidraGoPlugin Exception",
				"Unable to create GhidraGoListener", e);
		}
	}

	private void projectClosed() {
		if (this.listener != null) {
			listener.dispose();
			listener = null;
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProjectPluginEvent) {
			if (((ProjectPluginEvent) event).getProject() == null) {
				projectClosed();
			}
			else {
				projectOpened();
			}
		}
	}

}
