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

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.WindowPosition;
import generic.theme.GIcon;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;

class ReferenceProvider extends ComponentProviderAdapter {

	private static final Icon ICON = new GIcon("icon.plugin.symboltable.referencetable.provider");

	private SymbolTablePlugin plugin;
	private SymbolReferenceModel referenceKeyModel;
	private ReferencePanel referencePanel;
	private SymbolRenderer renderer;

	ReferenceProvider(SymbolTablePlugin plugin) {
		super(plugin.getTool(), "Symbol References", plugin.getName(), ProgramActionContext.class);
		this.plugin = plugin;

		setIcon(ICON);
		addToToolbar();
		setHelpLocation(new HelpLocation(plugin.getName(), "Symbol_References"));
		setWindowGroup("symbolTable");
		setIntraGroupPosition(WindowPosition.RIGHT);

		renderer = new SymbolRenderer();

		referenceKeyModel =
			new SymbolReferenceModel(plugin.getBlockModelService(), plugin.getTool());
		referencePanel =
			new ReferencePanel(this, referenceKeyModel, renderer);

		addToTool();
	}

	void dispose() {
		referencePanel.dispose();
		plugin = null;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Program program = plugin.getProgram();
		if (program == null) {
			return null;
		}

		List<Reference> selectedReferences = getSelectedReferences();
		return new ReferenceTableContext(this, selectedReferences);
	}

	private List<Reference> getSelectedReferences() {

		List<Reference> list = new ArrayList<>();
		GhidraTable table = getTable();
		int[] rows = table.getSelectedRows();
		for (int row : rows) {
			Reference ref = referenceKeyModel.getRowObject(row);
			list.add(ref);
		}
		return list;
	}

	void setCurrentSymbol(Symbol symbol) {
		referenceKeyModel.setCurrentSymbol(symbol);
	}

	void symbolChanged(Symbol symbol) {
		if (isVisible()) {
			referenceKeyModel.symbolChanged(symbol);
		}
	}

	void symbolRemoved(long symbolId) {
		if (isVisible()) {
			referenceKeyModel.symbolRemoved(symbolId);
		}
	}

	void symbolAdded(Symbol sym) {
		if (isVisible()) {
			referenceKeyModel.symbolAdded(sym);
		}
	}

	void setProgram(Program program, SymbolInspector inspector) {
		renderer.setSymbolInspector(inspector);
		if (isVisible()) {
			referenceKeyModel.setProgram(program);
		}
	}

	Program getProgram() {
		return referenceKeyModel.getProgram();
	}

	void reload() {
		if (isVisible()) {
			referenceKeyModel.reload();
		}
	}

	void showReferencesTo() {
		referenceKeyModel.showReferencesTo();
	}

	void showInstructionsFrom() {
		referenceKeyModel.showInstructionReferencesFrom();
	}

	void showDataFrom() {
		referenceKeyModel.showDataReferencesFrom();
	}

	public GhidraTable getTable() {
		return referencePanel.getTable();
	}

	void deleteRows(List<Reference> refs) {

		CompoundCmd<Program> compoundCmd = new CompoundCmd<>("Delete References");
		for (Reference ref : refs) {
			RemoveReferenceCmd cmd = new RemoveReferenceCmd(ref);
			compoundCmd.add(cmd);
			referenceKeyModel.removeObject(ref);
		}
		tool.execute(compoundCmd, getProgram());
	}

	private String generateSubTitle() {
		return "(" + referenceKeyModel.getDescription() + ")";
	}

	void open() {
		setVisible(true);
	}

	boolean isBusy() {
		return referenceKeyModel.isBusy();
	}

	@Override
	public void componentHidden() {
		referenceKeyModel.setProgram(null);
	}

	@Override
	public void componentShown() {
		referenceKeyModel.setProgram(plugin.getProgram());

		// Note: this is a bit of a hack--if we do this during a tool's restore process, then
		//       there is a chance that the Symbol Provider has not yet been re-loaded.   This
		//       is only needed due to the odd dependency of this provider upon the Symbol Provider.
		Swing.runLater(plugin::openSymbolProvider);
	}

	@Override
	public JComponent getComponent() {
		return referencePanel;
	}

	public void updateTitle() {
		setSubTitle(generateSubTitle());
	}
}
