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

import java.awt.BorderLayout;
import java.awt.Font;
import java.io.IOException;
import java.util.List;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;

/**
 * Extension of the {@link ProjectAccessPanel} that only shows the user access list.
 *
 */
public class ViewProjectAccessPanel extends ProjectAccessPanel {

	/** 
	 * Construct a new panel.
	 * 
	 * @param repository handle to the repository adapter
	 * @param tool the plugin tool
	 * @throws IOException if there's an error processing repository information
	 */
	public ViewProjectAccessPanel(RepositoryAdapter repository, PluginTool tool)
			throws IOException {
		super(null, repository, tool);
	}

	/**
	 * Constructs a new panel.
	 * 
	* @param knownUsers names of the users that are known to the remote server
	 * @param currentUser the current user
	 * @param allUsers all users known to the repository
	 * @param repositoryName the name of the repository
	 * @param anonymousServerAccessAllowed true if the server allows anonymous access
	 * @param anonymousAccessEnabled true if the repository allows anonymous access 
	 * (ignored if anonymousServerAccessAllowed is false)
	 * @param tool the current tool
	 */
	public ViewProjectAccessPanel(String[] knownUsers, String currentUser, List<User> allUsers,
			String repositoryName, boolean anonymousServerAccessAllowed,
			boolean anonymousAccessEnabled, PluginTool tool) {

		super(knownUsers, currentUser, allUsers, repositoryName, anonymousServerAccessAllowed,
			anonymousAccessEnabled, tool);
	}

	/**
	 * Creates the main gui panel, containing the known users, button, and user access 
	 * panels.
	 */
	@Override
	protected void createMainPanel(String[] knownUsers, boolean anonymousServerAccessAllowed) {

		JPanel mainPanel = new JPanel();
		mainPanel.setLayout(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

		userAccessPanel = new UserAccessPanel(currentUser);
		mainPanel.add(userAccessPanel, BorderLayout.CENTER);

		if (anonymousServerAccessAllowed && origAnonymousAccessEnabled) {
			JLabel anonymousAccessLabel = new GDLabel("Anonymous Read-Only Access Enabled");
			anonymousAccessLabel.setBorder(BorderFactory.createEmptyBorder(5, 2, 0, 0));
			Font f = anonymousAccessLabel.getFont().deriveFont(Font.ITALIC);
			anonymousAccessLabel.setFont(f);

			mainPanel.add(anonymousAccessLabel, BorderLayout.SOUTH);
		}

		add(mainPanel);
	}
}
