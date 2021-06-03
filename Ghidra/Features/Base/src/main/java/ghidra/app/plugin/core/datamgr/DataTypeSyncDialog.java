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
package ghidra.app.plugin.core.datamgr;

import java.awt.BorderLayout;
import java.util.*;

import javax.swing.JPanel;
import javax.swing.JSplitPane;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.util.HelpLocation;

/**
 * The DataTypeSyncDialog displays a table with the data types that need to be synchronized 
 * between a program and an associated archive that was used as a source of data types for 
 * the program. Synchronizing data types means either Committing changes made to program 
 * data types back to the associated source archive data types or Updating program data types 
 * with changes that were made to the associated source data type in the archive.
 */
public class DataTypeSyncDialog extends DialogComponentProvider implements DataTypeSyncListener {

	private DataTypeManagerPlugin plugin;
	private JPanel mainPanel;
	private DataTypeSyncPanel syncPanel;
	private DataTypeComparePanel comparePanel;
	private final String operationName;

	private boolean cancelled;
	private List<DataTypeSyncInfo> selectedInfos = Collections.emptyList();

	public DataTypeSyncDialog(DataTypeManagerPlugin plugin, String clientName, String sourceName,
			List<DataTypeSyncInfo> list, Set<DataTypeSyncInfo> preselectedInfos,
			String operationName, String title) {
		super(title, true);
		this.plugin = plugin;
		this.operationName = operationName;

		syncPanel = new DataTypeSyncPanel(list, preselectedInfos, this);
		comparePanel = new DataTypeComparePanel(clientName, sourceName);
		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, syncPanel, comparePanel);
		splitPane.setResizeWeight(0.6);
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(splitPane, BorderLayout.CENTER);
		addWorkPanel(mainPanel);
		initialize();
		createActions();
	}

	@Override
	public void close() {
		super.close();
		syncPanel.dispose();
	}

	private void initialize() {
		addOKButton();
		setOkButtonText(operationName);
		addCancelButton();
		setHelpLocation(new HelpLocation(plugin.getName(), "Commit_Changes_To_Archive"));
	}

	private void createActions() {
		DockingAction selectAllAction = new DockingAction("Select All", "Sync Dialog", false) {
			@Override
			public void actionPerformed(ActionContext context) {
				syncPanel.selectAll();
			}
		};
		selectAllAction.setPopupMenuData(new MenuData(new String[] { "Select All" }));
		addAction(selectAllAction);

		DockingAction deselectAllAction = new DockingAction("Deselect All", "Sync Dialog", false) {
			@Override
			public void actionPerformed(ActionContext context) {
				syncPanel.deselectAll();
			}
		};
		deselectAllAction.setPopupMenuData(new MenuData(new String[] { "Deselect All" }));
		addAction(deselectAllAction);

	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.datamgr.DataTypeSyncListener#dataTypeSelected(ghidra.program.model.data.DataType)
	 */
	@Override
	public void dataTypeSelected(DataTypeSyncInfo syncInfo) {
		if (syncInfo != null) {
			comparePanel.setDataTypes(syncInfo.getRefDataType(), syncInfo.getSourceDataType());
		}
		else {
			comparePanel.setDataTypes(null, null);
		}
	}

	@Override
	protected void okCallback() {
		selectedInfos = syncPanel.getSelectedInfos();
		close();
	}

	@Override
	protected void cancelCallback() {
		cancelled = true;
		close();
	}

	public List<DataTypeSyncInfo> getSelectedInfos() {
		return selectedInfos;
	}
}
