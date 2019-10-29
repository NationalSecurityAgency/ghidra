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
import java.awt.Component;
import java.util.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.tool.ToolConstants;
import docking.widgets.table.*;
import ghidra.framework.model.*;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.HelpLocation;

public class PickToolDialog extends DialogComponentProvider {

	private final FrontEndTool tool;
	private ToolTableModel model;
	private GTable table;
	private ToolTemplate selectedTemplate;
	private final Class<? extends DomainObject> domainClass;

	protected PickToolDialog(FrontEndTool tool, Class<? extends DomainObject> domainClass) {
		super("Pick Tool", true);
		this.tool = tool;
		this.domainClass = domainClass;

		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Set Tool Associations"));

		addWorkPanel(createWorkPanel());

		addOKButton();
		addCancelButton();

		setPreferredSize(300, 400);
		setRememberLocation(false);
	}

	private JComponent createWorkPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		model = new ToolTableModel();
		table = new GTable(model);

		table.setRowHeight(28); // make big enough for tool icons
		table.setColumnHeaderPopupEnabled(false); // don't allow column configuration
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setDefaultRenderer(GhidraToolTemplate.class, new ToolTemplateRenderer());

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			int selectedRow = table.getSelectedRow();
			ToolTemplate template = model.getRowObject(selectedRow);
			okButton.setEnabled(template != null);
		});

		loadList();

		mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);

		return mainPanel;
	}

	private void loadList() {
		Project project = tool.getProject();
		ToolServices toolServices = project.getToolServices();
		Set<ToolTemplate> compatibleTools = toolServices.getCompatibleTools(domainClass);
		model.setData(new ArrayList<>(compatibleTools));
	}

	void showDialog() {
		clearStatusText();
		tool.showDialog(this);
	}

	@Override
	protected void okCallback() {
		int selectedRow = table.getSelectedRow();
		selectedTemplate = model.getRowObject(selectedRow);
		close();
	}

	ToolTemplate getSelectedToolTemplate() {
		return selectedTemplate;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ToolTableModel extends AbstractSortedTableModel<ToolTemplate> {

		private List<ToolTemplate> data;

		ToolTableModel() {
			super(0);
			this.data = Collections.emptyList();
		}

		void setData(List<ToolTemplate> data) {
			this.data = data;
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return "Tool Picker";
		}

		@Override
		public Object getColumnValueForRow(ToolTemplate t, int column) {
			return t;
		}

		@Override
		public String getColumnName(int column) {
			return "Tool";
		}

		@Override
		public Class<?> getColumnClass(int column) {
			return GhidraToolTemplate.class;
		}

		@Override
		public List<ToolTemplate> getModelData() {
			return data;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return columnIndex == 0;
		}

		@Override
		public int getColumnCount() {
			return 1;
		}

		@Override
		public int getRowCount() {
			return data.size();
		}

		@Override
		protected Comparator<ToolTemplate> createSortComparator(int column) {
			return new ToolTemplateComparator();
		}
	}

	private class ToolTemplateComparator implements Comparator<ToolTemplate> {
		@Override
		public int compare(ToolTemplate o1, ToolTemplate o2) {
			return o1.getName().compareTo(o2.getName());
		}
	}

	private class ToolTemplateRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			ToolTemplate template = (ToolTemplate) value;
			if (template == null) {
				return renderer;
			}

			renderer.setIcon(template.getIcon());
			renderer.setText(template.getName());

			return renderer;
		}
	}
}
