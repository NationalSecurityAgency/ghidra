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
package ghidra.framework.task.gui;

import java.awt.*;

import javax.swing.*;

import docking.widgets.list.GListCellRenderer;
import ghidra.framework.task.GTaskManager;
import ghidra.framework.task.GTaskResult;
import resources.Icons;
import resources.ResourceManager;

public class GTaskResultPanel extends JPanel {
	private JList<GTaskResultInfo> jList;
	private CompletedTaskListModel model;

	public GTaskResultPanel(GTaskManager taskMgr) {
		super(new BorderLayout());
		model = new CompletedTaskListModel(taskMgr);
		jList = new JList<>(model);
		jList.setCellRenderer(new GTaskResultCellRenderer());
		JScrollPane scroll = new JScrollPane(jList);
		add(scroll);
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	}

	static class GTaskResultCellRenderer extends GListCellRenderer<GTaskResultInfo> {
		private static final Icon CANCELLED_ICON =
			ResourceManager.loadImage("images/dialog-cancel.png");
		private static final Icon EXCEPTION_ICON = Icons.ERROR_ICON;
		private static final Icon COMPLETED_ICON =
			ResourceManager.loadImage("images/checkmark_green.gif");

		@Override
		protected String getItemText(GTaskResultInfo value) {
			return value.toString();
		}

		@Override
		public Component getListCellRendererComponent(JList<? extends GTaskResultInfo> list,
				GTaskResultInfo value, int index, boolean isSelected, boolean cellHasFocus) {
			setIcon(getIcon(value.getResult()));
			setBackground(Color.white);
			return this;
		}

		private Icon getIcon(GTaskResult result) {
			if (result == null) {
				return null;
			}
			if (result.wasCancelled()) {
				return CANCELLED_ICON;
			}
			if (result.getException() != null) {
				return EXCEPTION_ICON;
			}
			return COMPLETED_ICON;
		}
	}
}
