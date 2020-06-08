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
package ghidra.app.plugin.core.script;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.MultiLineLabel;
import docking.widgets.list.ListPanel;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.util.HelpLocation;

public class PickProviderDialog extends DialogComponentProvider {
	private static String lastSelectedProviderDescription;

	private List<GhidraScriptProvider> providers;
	private ListPanel listPanel;
	private JComponent parent;
	private boolean wasCancelled;

	PickProviderDialog(JComponent parent, HelpLocation help) {
		super("New Script: Type");
		this.parent = parent;

		providers = GhidraScriptUtil.getProviders();
		DefaultListModel<GhidraScriptProvider> listModel = new DefaultListModel<>();
		for (GhidraScriptProvider provider : providers) {
			listModel.addElement(provider);
		}

		addWorkPanel(buildWorkPanel(listModel));
		addOKButton();
		addCancelButton();

		rootPanel.setPreferredSize(new Dimension(300, 225));
		setHelpLocation(help);
	}

	/**
	 * Constructor used in testing only!
	 * 
	 * @param testItems values to populate model with
	 * @param defaultItem the default selection
	 */
	public PickProviderDialog(List<String> testItems, String defaultItem) {
		super("New Script: Type");

		DefaultListModel<String> listModel = new DefaultListModel<>();
		for (String item : testItems) {
			listModel.addElement(item);
		}

		addWorkPanel(buildWorkPanel(listModel));
		addOKButton();
		addCancelButton();

		rootPanel.setPreferredSize(new Dimension(300, 225));

		if (defaultItem != null) {
			listPanel.setSelectedValue(defaultItem);
		}
	}

	/**
	 * For testing...
	 * 
	 * @param provider the provider selection 
	 */
	void setSelectedProvider(GhidraScriptProvider provider) {
		listPanel.setSelectedValue(provider);
	}

	GhidraScriptProvider getSelectedProvider() {
		if (providers.size() == 1) {
			return providers.get(0);
		}

		selectBestProvider();

		DockingWindowManager.showDialog(parent, this);
		if (wasCancelled) {
			return null;
		}
		return (GhidraScriptProvider) listPanel.getSelectedValue();
	}

	/**
	 * close any open dialog
	 */
	public void dispose() {
		close();
	}

	private void selectBestProvider() {
		if (lastSelectedProviderDescription != null) {
			for (GhidraScriptProvider provider : providers) {
				if (provider.getDescription().equals(lastSelectedProviderDescription)) {
					listPanel.setSelectedValue(provider);
					return;
				}
			}
		}

		for (GhidraScriptProvider provider : providers) {
			if ("Java".equals(provider.getDescription())) {
				listPanel.setSelectedValue(provider);
				return;
			}
		}
	}

	@Override
	protected void cancelCallback() {
		wasCancelled = true;
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		GhidraScriptProvider provider = (GhidraScriptProvider) listPanel.getSelectedValue();
		if (provider != null) {
			lastSelectedProviderDescription = provider.getDescription();
		}
		close();
	}

	private JPanel buildWorkPanel(DefaultListModel<?> listModel) {
		listPanel = new ListPanel();
		listPanel.setListModel(listModel);
		listPanel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		listPanel.setSelectedIndex(0);
		listPanel.setDoubleClickActionListener(e -> close());
		JPanel workPanel = new JPanel(new BorderLayout());
		MultiLineLabel mll = new MultiLineLabel("\nPlease select a script type:");
		workPanel.add(mll, BorderLayout.NORTH);
		workPanel.add(listPanel, BorderLayout.CENTER);
		return workPanel;
	}

}
