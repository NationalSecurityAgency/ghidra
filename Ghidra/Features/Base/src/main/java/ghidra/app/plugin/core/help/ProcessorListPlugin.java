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
package ghidra.app.plugin.core.help;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.util.*;

import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.dnd.GClipboard;
import docking.dnd.StringTransferable;
import docking.tool.ToolConstants;
import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.GTable;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.util.HelpTopics;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Displays list of installed processor modules",
	description = "This plugin provides a Help action that displays a list of installed processor modules"
)
//@formatter:on
public class ProcessorListPlugin extends Plugin implements FrontEndable {

	public final static String PLUGIN_NAME = "ProgramListPlugin";
	public final static String ACTION_NAME = "Installed Processors";

	private DockingAction processorListAction;

	private ProcessorListDialogProvider dialogProvider;

	public ProcessorListPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		setupActions();
	}

	@Override
	public void dispose() {
		tool.removeAction(processorListAction);
		processorListAction.dispose();
		super.dispose();
	}

	private void setupActions() {

		processorListAction = new DockingAction(ACTION_NAME, PLUGIN_NAME) {
			@Override
			public void actionPerformed(ActionContext context) {
				showProcessorList();
			}
		};

		processorListAction.setEnabled(true);

		processorListAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_HELP, ACTION_NAME }, null, "AAAZ"));

		processorListAction.setHelpLocation(new HelpLocation(HelpTopics.ABOUT, "ProcessorList"));
		processorListAction.setDescription(getPluginDescription().getDescription());
		tool.addAction(processorListAction);
	}

	private synchronized void dialogClosed() {
		dialogProvider = null;
	}

	private synchronized void showProcessorList() {
		if (dialogProvider == null) {
			dialogProvider = new ProcessorListDialogProvider();
		}
		tool.showDialog(dialogProvider);
	}

	private void copy(boolean asHtml) {
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		Transferable transferable = new StringTransferable(getProcessorList(asHtml));
		systemClipboard.setContents(transferable, null);
	}

	private Set<Processor> getProcessors() {
		TreeSet<Processor> processors = new TreeSet<>();
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		for (LanguageDescription languageDescription : languageService.getLanguageDescriptions(
			true)) {
			processors.add(languageDescription.getProcessor());
		}
		return processors;
	}

	private String getProcessorList(boolean asHtml) {
		StringBuilder strBuilder = new StringBuilder();
		if (asHtml) {
			strBuilder.append("<HTML><BODY>\n");
			strBuilder.append("<table width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">\n<tr>");
		}

		Set<Processor> processors = getProcessors();
		int itemsPerColum = (processors.size() + 2) / 3;
		int colCnt = 0;

		for (Processor processor : processors) {
			if (asHtml) {
				if ((colCnt % itemsPerColum) == 0) {
					if (colCnt != 0) {
						strBuilder.append("</ul>\n</td>");
					}
					strBuilder.append("<td width=\"33%\">\n<ul>");
				}
				strBuilder.append("<li>");
			}
			++colCnt;
			strBuilder.append(processor.toString());
			if (asHtml) {
				strBuilder.append("</li>");
			}
			strBuilder.append("\n");
		}
		if (asHtml) {
			strBuilder.append("</ul>\n</td></tr>\n</table>");
			strBuilder.append("</BODY></HTML>");
		}
		return strBuilder.toString();
	}

	class ProcessorListDialogProvider extends DialogComponentProvider {

		ProcessorListDialogProvider() {
			super("Installed Processor Modules", false, false, true, false);
			ProcessorListTableProvider tableProvider =
				new ProcessorListTableProvider(tool, getName());
			setRememberLocation(true);
			addWorkPanel(tableProvider.getComponent());
//			addWorkPanel(buildList());

			setHelpLocation(new HelpLocation(HelpTopics.ABOUT, "ProcessorList"));

			if (SystemUtilities.isInDevelopmentMode()) {

				JButton copyButton = new JButton("Copy");
				copyButton.addActionListener(e -> copy(false));
				addButton(copyButton);

				JButton copyHtmlButton = new JButton("Copy as HTML");
				copyHtmlButton.addActionListener(e -> copy(true));
				addButton(copyHtmlButton);
			}

			JButton closeButton = new JButton("Close");
			closeButton.addActionListener(e -> close());
			addButton(closeButton);
		}

		@Override
		protected void dialogClosed() {
			super.dialogClosed();
			ProcessorListPlugin.this.dialogClosed();
		}

	}

	public class ProcessorListTableProvider extends ComponentProviderAdapter {
		GTable table;
		private ProcessorListTableModel processorTableModel;
		private JScrollPane scrollPane;

		public ProcessorListTableProvider(PluginTool tool, String owner) {
			super(tool, "Processor Table", owner);
			buildTable();
		}

		@Override
		public JComponent getComponent() {
			return scrollPane;
		}

		private void buildTable() {

			TreeSet<Processor> processors = new TreeSet<>();
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			for (LanguageDescription languageDescription : languageService.getLanguageDescriptions(
				true)) {
				processors.add(languageDescription.getProcessor());
			}

			processorTableModel = new ProcessorListTableModel(new ArrayList<>(processors));

			table = new GTable(processorTableModel);
			scrollPane = new JScrollPane(table);
			table.getSelectionManager().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		}

	}

	public class ProcessorListTableModel extends AbstractSortedTableModel<Processor> {

		private static final int PROCESSOR_COL = 0;

		private List<Processor> processors;

		public ProcessorListTableModel(List<Processor> processors) {
			this.processors = processors;
		}

		@Override
		public Object getColumnValueForRow(Processor p, int columnIndex) {
			switch (columnIndex) {
				case PROCESSOR_COL:
					return p.toString();
			}
			return null;
		}

		@Override
		public String getName() {
			return "Processors";
		}

		@Override
		public List<Processor> getModelData() {
			return processors;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return false; // maybe later when we add more columns
		}

		@Override
		public int getColumnCount() {
			return 1;
		}

		@Override
		public int getRowCount() {
			return processors.size();
		}

		@Override
		public String getColumnName(int column) {
			switch (column) {
				case PROCESSOR_COL:
					return "Processor";
			}
			return null;
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			switch (columnIndex) {
				case PROCESSOR_COL:
					return String.class;
			}
			return Object.class;
		}

	}

}
