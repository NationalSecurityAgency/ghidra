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
package ghidra.framework.main.wizard.project;

import java.awt.BorderLayout;

import javax.swing.JPanel;

import ghidra.framework.main.ServerInfoComponent;
import ghidra.framework.model.ServerInfo;
import utility.function.Callback;

/**
 * Panel that allows the user to specify the host name and port
 * number for the remote repository server. Used by the {@link ServerStep} of
 * either the new project wizard, the "convert to shared" wizard, or the "change repository"
 * wizard.
 */
public class ServerInfoPanel extends JPanel {

	private ServerInfoComponent serverInfoComponent;

	public ServerInfoPanel(Callback statusChangedCallback) {
		super(new BorderLayout(10, 10));
		setBorder(ProjectWizardModel.STANDARD_BORDER);
		serverInfoComponent = new ServerInfoComponent();
		add(serverInfoComponent, BorderLayout.CENTER);
		serverInfoComponent.setChangeListener(e -> statusChangedCallback.call());
	}

	public boolean isValidInformation() {
		return serverInfoComponent.isValidInformation();
	}

	public String getStatusMessge() {
		return serverInfoComponent.getStatusMessage();
	}

	public String getServerName() {
		return serverInfoComponent.getServerName();
	}

	public int getPortNumber() {
		return serverInfoComponent.getPortNumber();
	}

	/**
	 * Set the field values using the given server info.
	 */
	public void setServerInfo(ServerInfo info) {
		serverInfoComponent.setServerInfo(info);
	}
}
