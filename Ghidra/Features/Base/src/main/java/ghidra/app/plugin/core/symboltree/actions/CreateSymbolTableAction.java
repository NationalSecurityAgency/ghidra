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
package ghidra.app.plugin.core.symboltree.actions;

import java.util.*;

import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.action.KeyBindingType;
import docking.action.MenuData;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.context.ProgramSymbolContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.symtable.*;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.services.GoToService;
import ghidra.app.util.SymbolInspector;
import ghidra.app.util.query.TableService;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

public class CreateSymbolTableAction extends ProgramSymbolContextAction {

	private Plugin plugin;

	public CreateSymbolTableAction(Plugin plugin) {
		super("Create Table", plugin.getName(), KeyBindingType.SHARED);
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Create Table" },
			SymbolTreeContextAction.MIDDLE_MENU_GROUP));

		// Note: We need to set the help location instead of using the default behavior, which is to
		// use the plugin's name.  By doing this we can have all different uses of this action 
		// point to one help location.
		setHelpLocation(new HelpLocation("SymbolTablePlugin", "Temporary_Symbol_Table"));
	}

	@Override
	protected boolean isEnabledForContext(ProgramSymbolActionContext context) {
		return context.getSymbolCount() != 0;
	}

	@Override
	protected void actionPerformed(ProgramSymbolActionContext context) {

		HashSet<SymbolRowObject> rowObjects = new HashSet<>();
		Iterable<Symbol> symbols = context.getSymbols();
		for (Symbol symbol : symbols) {
			rowObjects.add(new SymbolRowObject(symbol));
		}

		PluginTool tool = plugin.getTool();
		Program program = context.getProgram();
		TransientSymbolTableModel model = new TransientSymbolTableModel(tool, program, rowObjects);

		Navigatable navigatable = null;
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			navigatable = goToService.getDefaultNavigatable();
		}

		TableService service = tool.getService(TableService.class);
		if (service == null) {
			Msg.showError(this, null, "Table Service Not Installed",
				"You must have a Table Service installed to create a Symbol Table");
			return;
		}

		TableComponentProvider<SymbolRowObject> provider =
			service.showTable("Symbols", "Symbols", model, "Symbols", navigatable);

		provider.setActionContextProvider(mouseEvent -> {

			GThreadedTablePanel<SymbolRowObject> tablePanel = provider.getThreadedTablePanel();
			GTable table = tablePanel.getTable();
			List<Symbol> selectedSymbols = getSelectedSymbols(table, model);

			return new ProgramSymbolActionContext(provider, program, selectedSymbols, table);
		});

		// replace the generic provider help with this action's help
		provider.setHelpLocation(getHelpLocation());

		addActions(provider, model);

		GhidraThreadedTablePanel<SymbolRowObject> tablePanel = provider.getThreadedTablePanel();
		GhidraTable table = tablePanel.getTable();

		configureSymbolTable(tool, table, model, program);
	}

	private void addActions(TableComponentProvider<SymbolRowObject> provider,
			TransientSymbolTableModel model) {

		provider.installRemoveItemsAction();

		CreateSymbolTableAction tableAction = new CreateSymbolTableAction(plugin);
		provider.getTool().addLocalAction(provider, tableAction);
	}

	private void configureSymbolTable(PluginTool tool, GhidraTable table,
			TransientSymbolTableModel model, Program program) {

		new TransientSymbolTableDnDAdapter(table, model);

		SymbolInspector symbolInspector = new SymbolInspector(tool, table);
		SymbolRenderer renderer = model.getSymbolRenderer();
		renderer.setSymbolInspector(symbolInspector);

		TableColumnModel columnModel = table.getColumnModel();
		int n = table.getColumnCount();
		for (int i = 0; i < n; i++) {
			TableColumn column = columnModel.getColumn(i);
			column.setCellRenderer(renderer);
			if (column.getModelIndex() == AbstractSymbolTableModel.LABEL_COL) {
				column.setCellEditor(new SymbolEditor());
			}
		}
	}

	private List<Symbol> getSelectedSymbols(GTable table, TransientSymbolTableModel model) {
		List<Symbol> list = new ArrayList<>();
		int[] rows = table.getSelectedRows();
		for (int row : rows) {
			SymbolRowObject rowObject = model.getRowObject(row);
			Symbol s = rowObject.getSymbol();
			if (s != null) {
				list.add(s);
			}
		}
		return list;
	}

}
