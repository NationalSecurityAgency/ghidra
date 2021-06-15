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
package ghidra.app.plugin.core.symtable;

import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.DockingUtils;
import docking.action.KeyBindingData;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramSymbolActionContext;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

class SymbolProvider extends ComponentProviderAdapter {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/table.png");

	private SymbolTablePlugin plugin;
	private SymbolRenderer renderer;
	private SymbolTableModel symbolKeyModel;
	private SymbolPanel symbolPanel;

	SymbolProvider(SymbolTablePlugin plugin) {
		super(plugin.getTool(), "Symbol Table", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setKeyBinding(new KeyBindingData(KeyEvent.VK_T, DockingUtils.CONTROL_KEY_MODIFIER_MASK));

		setHelpLocation(new HelpLocation(plugin.getName(), "Symbol_Table"));
		setWindowGroup("symbolTable");
		renderer = new SymbolRenderer();

		symbolKeyModel = new SymbolTableModel(this, plugin.getTool());
		symbolPanel = new SymbolPanel(this, symbolKeyModel, renderer, plugin.getTool(),
			plugin.getGoToService());

		addToTool();
	}

	void updateTitle() {
		setSubTitle(generateSubTitle());
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}

		List<Symbol> symbols = symbolPanel.getSelectedSymbols();
		return new ProgramSymbolActionContext(this, program, symbols, getTable());
	}

	void deleteSymbols() {
		List<Symbol> rowObjects = symbolPanel.getSelectedSymbols();
		symbolKeyModel.delete(rowObjects);
	}

	void setFilter() {
		symbolPanel.setFilter();
	}

	Symbol getCurrentSymbol() {
		List<Symbol> rowObjects = symbolPanel.getSelectedSymbols();
		if (rowObjects != null && rowObjects.size() >= 1) {
			return rowObjects.get(0);
		}
		return null;
	}

	Symbol getSymbolForRow(int row) {
		return symbolKeyModel.getRowObject(row);
	}

	void setCurrentSymbol(Symbol symbol) {
		plugin.getReferenceProvider().setCurrentSymbol(symbol);
	}

	Symbol getSymbol(long id) {
		return symbolKeyModel.getSymbol(id);
	}

	void dispose() {
		symbolKeyModel.dispose();
		symbolPanel.dispose();
		plugin = null;
	}

	void reload() {
		if (isVisible()) {
			symbolKeyModel.reload();
		}
	}

	void symbolAdded(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolAdded(s);
		}
	}

	void symbolRemoved(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolRemoved(s);
		}
	}

	void symbolChanged(Symbol s) {
		if (isVisible()) {
			symbolKeyModel.symbolChanged(s);
		}
	}

	void setProgram(Program program, SymbolInspector inspector) {
		renderer.setSymbolInspector(inspector);
		if (isVisible()) {
			symbolKeyModel.reload(program);
		}
	}

	GhidraTable getTable() {
		return symbolPanel.getTable();
	}

	SymbolFilter getFilter() {
		return symbolPanel.getFilter();
	}

	boolean isShowingDynamicSymbols() {
		return getFilter().acceptsDefaultLabelSymbols();
	}

	private String generateSubTitle() {
		SymbolFilter filter = symbolKeyModel.getFilter();
		int rowCount = symbolKeyModel.getRowCount();
		int unfilteredCount = symbolKeyModel.getUnfilteredRowCount();

		if (rowCount != unfilteredCount) {
			return " (Text filter matched " + rowCount + " of " + unfilteredCount + " symbols)";
		}
		if (filter.acceptsAll()) {
			return "(" + symbolPanel.getActualSymbolCount() + " Symbols)";
		}
		return "(Filter settings matched " + symbolPanel.getActualSymbolCount() + " Symbols)";

	}

	void open() {
		if (!isVisible()) {
			setVisible(true);
		}
	}

	boolean isBusy() {
		return symbolKeyModel.isBusy();
	}

	@Override
	public void componentHidden() {
		symbolKeyModel.reload(null);
		if (plugin != null) {
			plugin.symbolProviderClosed();
		}
	}

	@Override
	public void componentShown() {
		symbolKeyModel.reload(plugin.getProgram());
	}

	@Override
	public JComponent getComponent() {
		return symbolPanel;
	}

	void readConfigState(SaveState saveState) {
		symbolPanel.readConfigState(saveState);
	}

	void writeConfigState(SaveState saveState) {
		symbolPanel.writeConfigState(saveState);
	}
}
