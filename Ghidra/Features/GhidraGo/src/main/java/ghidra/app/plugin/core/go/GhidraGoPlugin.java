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
import ghidra.framework.main.*;
import ghidra.framework.model.ToolServices;
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
	shortDescription = "Listens for new GhidraURL's to launch using ToolServices",
	description = "Polls the ghidraGo directory for any url files written by the GhidraGoClient and " +
		"processes them in Ghidra",
	eventsConsumed = {ProjectPluginEvent.class})
//@formatter:on
public class GhidraGoPlugin extends Plugin implements ApplicationLevelOnlyPlugin {
	private GhidraGoListener listener;

	public GhidraGoPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
	}

	@Override
	protected void dispose() {
		if (this.listener != null) {
			listener.dispose();
			listener = null;
		}
		super.dispose();
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProjectPluginEvent) {
			if (((ProjectPluginEvent) event).getProject() == null) {
				dispose();
			}
			else {
				try {
					listener = new GhidraGoListener((url) -> {
						processGhidraURL(url);
					});
				}
				catch (IOException e) {
					Msg.showError(this, null, "GhidraGoPlugin Exception",
						"Unable to create Listener", e);
				}
			}
		}
	}

	/**
	 * If the active project is null, do nothing.
	 * Otherwise, try and open the url using {@link ToolServices} launchDefaultToolWithURL function.
	 * @param ghidraURL the GhidraURL to open.
	 */
	private void processGhidraURL(URL ghidraURL) {

		Msg.info(this, "GhidraGo processing " + ghidraURL);

		try {
			Msg.info(this,
				"Accepting the resource at " + GhidraURL.getProjectURL(ghidraURL));
			Swing.runNow(() -> {
				FrontEndTool frontEnd = AppInfo.getFrontEndTool();
				frontEnd.toFront();
				frontEnd.getToolServices().launchDefaultToolWithURL(ghidraURL);
			});
		}
		catch (IllegalArgumentException e) {
			Msg.showError(this, null, "GhidraGo Unable to process GhidraURL",
				"GhidraGo could not process " + ghidraURL, e);
		}
	}
}
