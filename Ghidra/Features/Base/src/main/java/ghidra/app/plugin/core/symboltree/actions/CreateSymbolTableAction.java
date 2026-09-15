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
import docking.tool.ToolConstants;
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
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;

public class CreateSymbolTableAction extends ProgramSymbolContextAction {

	private ServiceProvider services;

	public CreateSymbolTableAction(ServiceProvider services) {
		super("Create Table", ToolConstants.SHARED_OWNER, KeyBindingType.SHARED);
		this.services = services;

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

		Program program = context.getProgram();
		TransientSymbolTableModel model =
			new TransientSymbolTableModel(services, program, rowObjects);
		showTransientTable(services, "Symbols", context.getProgram(), model);
	}

	/**
	 * A utility method to show a table of symbols.
	 * @param services the service provider
	 * @param title the provider's title
	 * @param program the program
	 * @param model the model
	 * @return the new provider
	 */
	public static TableComponentProvider<SymbolRowObject> showTransientTable(
			ServiceProvider services, String title, Program program,
			TransientSymbolTableModel model) {

		TableService service = services.getService(TableService.class);
		if (service == null) {
			Msg.showError(CreateSymbolTableAction.class, null, "Table Service Not Installed",
				"You must have a Table Service installed to create a Symbol Table");
			return null;
		}

		Navigatable navigatable = null;
		GoToService goToService = services.getService(GoToService.class);
		if (goToService != null) {
			navigatable = goToService.getDefaultNavigatable();
		}

		TableComponentProvider<SymbolRowObject> provider =
			service.showTable(title, "Symbols", model, "Symbols", navigatable);

		provider.setActionContextProvider(mouseEvent -> {

			GThreadedTablePanel<SymbolRowObject> tablePanel = provider.getThreadedTablePanel();
			GTable table = tablePanel.getTable();
			List<Symbol> selectedSymbols = getSelectedSymbols(table, model);

			return new ProgramSymbolActionContext(provider, program, selectedSymbols, table);
		});

		// replace the generic provider help 
		provider.setHelpLocation(new HelpLocation("SymbolTablePlugin", "Temporary_Symbol_Table"));

		addActions(services, provider, model);

		GhidraThreadedTablePanel<SymbolRowObject> tablePanel = provider.getThreadedTablePanel();
		GhidraTable table = tablePanel.getTable();

		configureSymbolTable(services, table, model, program);

		return provider;
	}

	private static void addActions(ServiceProvider services,
			TableComponentProvider<SymbolRowObject> provider, TransientSymbolTableModel model) {

		provider.installRemoveItemsAction();

		CreateSymbolTableAction tableAction = new CreateSymbolTableAction(services);
		PluginTool tool = provider.getTool();
		tool.addLocalAction(provider, tableAction);

		SetSymbolPrimaryAction primaryAction = new SetSymbolPrimaryAction();
		tool.addLocalAction(provider, primaryAction);
	}

	private static void configureSymbolTable(ServiceProvider services, GhidraTable table,
			TransientSymbolTableModel model, Program program) {

		new TransientSymbolTableDnDAdapter(table, model);

		SymbolInspector symbolInspector = new SymbolInspector(services, table);
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

	private static List<Symbol> getSelectedSymbols(GTable table, TransientSymbolTableModel model) {
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
