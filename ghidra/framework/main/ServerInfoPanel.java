/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.model.ServerInfo;
import ghidra.util.HelpLocation;

import java.awt.BorderLayout;

import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.wizard.*;

/**
 * Wizard panel that allows the user to specify the host name and port
 * number for the remote repository server.
 */
public class ServerInfoPanel extends AbstractWizardJPanel {

	private ServerInfoComponent serverInfoComponent;
	private PanelManager panelManager;
	private HelpLocation helpLoc;

	public ServerInfoPanel(PanelManager panelManager) {
		super(new BorderLayout(10, 10));
		this.panelManager = panelManager;
		setBorder(NewProjectPanelManager.EMPTY_BORDER);
		buildMainPanel();
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getTitle()
	 */
	public String getTitle() {
		return "Specify Server Information";
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		if (helpLoc != null) {
			return helpLoc;
		}
		return new HelpLocation(GenericHelpTopics.FRONT_END, "ServerInfo");
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#initialize()
	 */
	public void initialize() {
		serverInfoComponent.setStatusListener(panelManager.getWizardManager());
	}

	/**
	 * Return whether the fields on this panel have valid information.
	 */
	public boolean isValidInformation() {
		return serverInfoComponent.isValidInformation();
	}

	/**
	 * Get the server name. 
	 */
	String getServerName() {
		return serverInfoComponent.getServerName();
	}

	/**
	 * Get the port number.
	 */
	int getPortNumber() {
		return serverInfoComponent.getPortNumber();
	}

	/**
	 * Set the field values using the given server info.
	 */
	public void setServerInfo(ServerInfo info) {
		serverInfoComponent.setServerInfo(info);
	}

	void setHelpLocation(HelpLocation helpLoc) {
		this.helpLoc = helpLoc;
	}

	private void buildMainPanel() {
		serverInfoComponent = new ServerInfoComponent();
		serverInfoComponent.setChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				WizardManager wm = panelManager.getWizardManager();
				if (wm.getCurrentWizardPanel() != null) {
					wm.validityChanged();
				}
			}
		});
		add(serverInfoComponent, BorderLayout.CENTER);
	}
}
