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
package ghidra.features.bsim.gui.search.dialog;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.EmptyBorderButton;
import docking.widgets.combobox.GComboBox;
import docking.widgets.textfield.FloatingPointTextField;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.facade.QueryDatabaseException;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.Task;
import resources.Icons;

/**
 * Base class for BSim Search dialogs that all have a server comboBox, and entries for the
 * similarity and confidence values.
 */
public abstract class AbstractBSimSearchDialog extends DialogComponentProvider {
	private final BSimServerManager serverManager;
	private GComboBox<BSimServerInfo> serverCombo;
	private BSimServerManagerListener serverInfoListener = this::serverListChanged;
	private ItemListener serverComboListener = this::comboChanged;

	protected BSimSearchService searchService;
	protected PluginTool tool;
	protected FloatingPointTextField similarityField;
	protected FloatingPointTextField confidenceField;
	protected BSimServerCache serverCache; // non-null when valid server is connected

	protected AbstractBSimSearchDialog(String title, PluginTool tool, BSimSearchService service,
			BSimServerManager serverManager) {

		super(title, true);
		this.tool = tool;
		this.searchService = service;
		this.serverManager = serverManager;
		serverManager.addListener(serverInfoListener);
		addWorkPanel(buildMainPanel());
		populateComboServerComboBox();

		addOKButton();
		addCancelButton();

		initializeConnection(searchService.getLastUsedServer());
		initializeSettings(searchService.getLastUsedSearchSettings());
	}

	protected void initializeSettings(BSimSearchSettings lastUsedSearchSettings) {
		similarityField.setValue(lastUsedSearchSettings.getSimilarity());
		confidenceField.setValue(lastUsedSearchSettings.getConfidence());
	}

	private JPanel buildMainPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildNorthPanel(), BorderLayout.NORTH);
		panel.add(buildCenterPanel(), BorderLayout.CENTER);
		return panel;
	}

	private Component buildNorthPanel() {
		JPanel panel = new JPanel(new VerticalLayout(10));
		panel.add(buildServerPanel());
		panel.add(createTitledPanel("Options", buildOptionsPanel(), false));
		return panel;
	}

	protected Component buildCenterPanel() {
		return new JPanel();
	}

	protected JPanel buildServerPanel() {
		JPanel panel = new JPanel(new PairLayout(10, 10));
		panel.add(new JLabel("BSim Server:"));
		panel.add(buildServerComponent());
		return panel;
	}

	protected JPanel buildOptionsPanel() {

		JPanel panel = new JPanel(new PairLayout(2, 10));

		similarityField = new FloatingPointTextField(10);
		similarityField.setValue(0.7);
		similarityField.setMinValue(0.0);
		similarityField.setMaxValue(1.0);

		confidenceField = new FloatingPointTextField(10);
		confidenceField.setValue(0);
		confidenceField.setMinValue(0.0);

		panel.add(new JLabel("Similarity Threshold (0-1):"));
		panel.add(similarityField);
		panel.add(new JLabel("Confidence Threshold:"));
		panel.add(confidenceField);
		return panel;
	}

	@Override
	public void dispose() {
		serverManager.removeListener(serverInfoListener);
		super.dispose();
	}

	private void serverListChanged() {
		populateComboServerComboBox();
	}

	private void populateComboServerComboBox() {
		serverCombo.removeItemListener(serverComboListener);

		DefaultComboBoxModel<BSimServerInfo> model = new DefaultComboBoxModel<>();

		List<BSimServerInfo> serverInfos = new ArrayList<>(serverManager.getServerInfos());
		Collections.sort(serverInfos);
		model.addElement(null); // allow no-selection (null entry / disconnected state)
		model.addAll(serverInfos);
		serverCombo.setModel(model);
		serverCombo.addItemListener(serverComboListener);
	}

	private void comboChanged(ItemEvent e) {
		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}
		Swing.runLater(() -> {
			BSimServerInfo selected = (BSimServerInfo) serverCombo.getSelectedItem();
			if (serverCache == null || !serverCache.getServerInfo().equals(selected)) {
				initializeConnection(selected);
			}
		});
		setStatusText("");
	}

	private void initializeConnection(BSimServerInfo info) {
		if (info != null) {
			try {
				setServerCache(new BSimServerCache(info));
				return;
			}
			catch (QueryDatabaseException e) {
				if (!e.getMessage().contains("cancelled")) {
					Msg.showError(this, rootPanel, "BSim Server Connection Failure",
						e.getMessage());
				}
			}
			catch (Exception e) {
				Msg.showError(this, rootPanel, "BSim Server Connection Failure",
					"Unexpected error while connecting to: " + info, e);
			}
		}
		setServerCache(null);
	}

	protected DatabaseInformation getDatabaseInformation() {
		if (serverCache != null) {
			return serverCache.getDatabaseInformation();
		}
		return null;
	}

	protected void updateSearchEnablement() {
		setOkEnabled(canQuery());
	}

	protected boolean canQuery() {
		if (serverCache == null) {
			setStatusText("Please select a Bsim Server.");
			return false;
		}
		return true;
	}

	protected void setServerCache(BSimServerCache serverCache) {
		this.serverCache = serverCache;
		setSelectedComboValue(serverCache != null ? serverCache.getServerInfo() : null);
		updateSearchEnablement();
	}

	private void setSelectedComboValue(BSimServerInfo info) {
		if (!Objects.equals(serverCombo.getSelectedItem(), info)) {
			serverCombo.removeItemListener(serverComboListener);
			serverCombo.setSelectedItem(info);
			serverCombo.addItemListener(serverComboListener);
		}
	}

	private JPanel buildServerComponent() {
		JPanel panel = new JPanel(new BorderLayout());
		JPanel comboPanel = new JPanel(new BorderLayout());
		comboPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
		serverCombo = new GComboBox<>();
		serverCombo.addItemListener(serverComboListener);
		comboPanel.add(serverCombo, BorderLayout.CENTER);
		panel.add(comboPanel, BorderLayout.CENTER);

		JButton button = new EmptyBorderButton(Icons.CONFIGURE_FILTER_ICON);
		button.setToolTipText("Show Server Manager Dialog");
		button.addActionListener(e -> managerServers());
		panel.add(button, BorderLayout.EAST);
		return panel;
	}

	protected JPanel createTitledPanel(String name, JComponent comp, boolean fullWidth) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(20, 5, 0, 0));
		JPanel titlePanel = new JPanel(new BorderLayout());
		JPanel contentPanel = new JPanel(new BorderLayout());

		panel.add(titlePanel, BorderLayout.NORTH);
		panel.add(contentPanel, BorderLayout.CENTER);

		contentPanel.setBorder(BorderFactory.createEmptyBorder(10, 15, 0, 0));

		contentPanel.add(comp, fullWidth ? BorderLayout.CENTER : BorderLayout.WEST);

		JLabel label = new JLabel(name);
		label.setFont(label.getFont().deriveFont(Font.BOLD));
		titlePanel.add(label, BorderLayout.NORTH);

		return panel;
	}

	private void managerServers() {
		BSimServerDialog dialog = new BSimServerDialog(tool, serverManager);
		DockingWindowManager.showDialog(dialog);
		BSimServerInfo lastAddedServer = dialog.getLastAdded();
		if (lastAddedServer != null) {
			initializeConnection(lastAddedServer);
		}
	}

//==================================================================================================
// test methods
//==================================================================================================	
	protected void setServer(BSimServerInfo info) {
		initializeConnection(info);
	}

	protected BSimServerInfo getServer() {
		return serverCache == null ? null : serverCache.getServerInfo();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	
	protected abstract class BSimQueryTask extends Task {
		protected Exception errorException;

		BSimQueryTask(String title) {
			super(title, true, true, false);
		}

		boolean hasError() {
			return errorException != null;
		}

		Exception getError() {
			return errorException;
		}

	}
}
