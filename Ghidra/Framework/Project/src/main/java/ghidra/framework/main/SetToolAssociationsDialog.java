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

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.tool.ToolConstants;
import docking.widgets.table.*;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.model.*;
import ghidra.framework.project.tool.GhidraToolTemplate;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

class SetToolAssociationsDialog extends DialogComponentProvider {

	private final FrontEndTool tool;
	private ToolAssociationTableModel model;
	private GTable table;

	SetToolAssociationsDialog(FrontEndTool tool) {
		super("Set Tool Associations", true);
		this.tool = tool;

		setHelpLocation(new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Set Tool Associations"));

		addWorkPanel(createWorkPanel());

		addOKButton();
		addCancelButton();

		setPreferredSize(400, 400);
		setRememberLocation(false);
	}

	private JComponent createWorkPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		model = new ToolAssociationTableModel();
		table = new GTable(model);

		final JButton editButton = new JButton("Edit");
		editButton.addActionListener(e -> {
			int selectedRow = table.getSelectedRow();
			ToolAssociationInfo info = model.getRowObject(selectedRow);
			if (info == null) {
				return;
			}

			ContentHandler contentHandler = info.getContentHandler();
			Class<? extends DomainObject> domainClass = contentHandler.getDomainObjectClass();
			PickToolDialog dialog = new PickToolDialog(tool, domainClass);
			dialog.showDialog();

			ToolTemplate template = dialog.getSelectedToolTemplate();
			if (template != null) {
				info.setCurrentTool(template);
				model.fireTableDataChanged();
			}
		});
		editButton.setEnabled(false);

		final JButton resetButton = new JButton("Restore Default");
		resetButton.addActionListener(e -> {
			int selectedRow = table.getSelectedRow();
			ToolAssociationInfo info = model.getRowObject(selectedRow);
			if (info != null) {
				info.restoreDefaultAssociation();
				table.repaint();
			}
		});
		resetButton.setEnabled(false);

		table.setRowHeight(28); // make big enough for tool icons
		table.setColumnHeaderPopupEnabled(false); // don't allow column configuration
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setDefaultRenderer(ContentHandler.class, new ContentHandlerRenderer());
		table.setDefaultRenderer(GhidraToolTemplate.class, new ToolTemplateRenderer());

		table.getSelectionModel().addListSelectionListener(e -> {
			if (e.getValueIsAdjusting()) {
				return;
			}

			int selectedRow = table.getSelectedRow();
			ToolAssociationInfo info = model.getRowObject(selectedRow);
			if (info == null) {
				editButton.setEnabled(false);
				resetButton.setEnabled(false);
				return;
			}

			editButton.setEnabled(true);
			resetButton.setEnabled(!info.isDefault());
		});

		loadList();

		JPanel buttonPanel = new JPanel();
		buttonPanel.add(editButton);
		buttonPanel.add(Box.createHorizontalStrut(5));
		buttonPanel.add(resetButton);

		mainPanel.add(new JScrollPane(table), BorderLayout.CENTER);
		mainPanel.add(buttonPanel, BorderLayout.SOUTH);

		return mainPanel;
	}

	private void loadList() {
		Project project = tool.getProject();
		ToolServices toolServices = project.getToolServices();
		Set<ToolAssociationInfo> infos = toolServices.getContentTypeToolAssociations();
		model.setData(new ArrayList<>(infos));
	}

	void showDialog() {
		clearStatusText();
		tool.showDialog(this);
	}

	@Override
	protected void okCallback() {
		applyUserChoices();
		close();
	}

	private void applyUserChoices() {
		Set<ToolAssociationInfo> set = new HashSet<>(model.getModelData());
		tool.getToolServices().setContentTypeToolAssociations(set);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ToolAssociationTableModel extends AbstractSortedTableModel<ToolAssociationInfo> {

		private List<ToolAssociationInfo> data;

		ToolAssociationTableModel() {
			super(0);
			this.data = Collections.emptyList();
		}

		void setData(List<ToolAssociationInfo> data) {
			this.data = data;
			fireTableDataChanged();
		}

		@Override
		public String getName() {
			return "Set Tool Association";
		}

		@Override
		public Object getColumnValueForRow(ToolAssociationInfo t, int column) {
			switch (column) {
				case 0:
					return t.getContentHandler();
				case 1:
					return t.getCurrentTemplate();
			}
			return null;
		}

		@Override
		public String getColumnName(int column) {
			switch (column) {
				case 0:
					return "Content Type";
				case 1:
					return "Tool";
			}
			return null;
		}

		@Override
		public Class<?> getColumnClass(int column) {
			switch (column) {
				case 0:
					return ContentHandler.class;
				case 1:
					return GhidraToolTemplate.class;
			}
			return null;
		}

		@Override
		public List<ToolAssociationInfo> getModelData() {
			return data;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return columnIndex == 0;
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public int getRowCount() {
			return data.size();
		}

		@Override
		protected Comparator<ToolAssociationInfo> createSortComparator(int column) {
			switch (column) {
				case 0:
					return new ContentHandlerComparator();
				case 1:
					return new ToolTemplateComparator();
			}
			return super.createSortComparator(column);
		}
	}

	private class ContentHandlerComparator implements Comparator<ToolAssociationInfo> {
		@Override
		public int compare(ToolAssociationInfo o1, ToolAssociationInfo o2) {
			return o1.getContentHandler().getContentType().compareTo(
				o2.getContentHandler().getContentType());
		}
	}

	private class ToolTemplateComparator implements Comparator<ToolAssociationInfo> {
		@Override
		public int compare(ToolAssociationInfo o1, ToolAssociationInfo o2) {
			return o1.getCurrentTemplate().getName().compareTo(o2.getCurrentTemplate().getName());
		}
	}

	private class ContentHandlerRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			//
			// Content Type: icon - name
			//
			ContentHandler handler = (ContentHandler) value;
			renderer.setIcon(handler.getIcon());
			renderer.setText(handler.getContentType());

			return renderer;
		}
	}

	private class ToolTemplateRenderer extends GTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			int row = data.getRowViewIndex();

			ToolTemplate template = (ToolTemplate) value;
			if (template == null) {
				renderDefaultTool(renderer, row);
				return renderer;
			}

			renderer.setIcon(template.getIcon());
			renderer.setText(template.getName());

			return renderer;
		}

		private void renderDefaultTool(JLabel renderer, int row) {
			ToolAssociationInfo info = model.getRowObject(row);
			ToolTemplate template = info.getDefaultTemplate();
			if (template == null) {
				return;
			}

			renderer.setForeground(Color.LIGHT_GRAY);

			Icon icon = null;
			if (template.getName().equals(info.getAssociatedToolName())) {
				icon = ResourceManager.getDisabledIcon(template.getIcon());
			}
			else {
				icon = ResourceManager.getDisabledIcon(ResourceManager.getScaledIcon(
					ResourceManager.loadImage("images/EmptyIcon.gif"), 24, 24));
			}

			renderer.setText(info.getAssociatedToolName());
			renderer.setIcon(icon);
		}
	}

}
