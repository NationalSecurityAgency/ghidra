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

import javax.swing.ImageIcon;
import javax.swing.JComponent;

import docking.ActionContext;
import docking.WindowPosition;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.util.SymbolInspector;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.table.GhidraTable;
import resources.ResourceManager;

class ReferenceProvider extends ComponentProviderAdapter {

	private static final ImageIcon ICON = ResourceManager.loadImage("images/table_go.png");

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
			new ReferencePanel(this, referenceKeyModel, renderer, plugin.getGoToService());

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
		return new ProgramActionContext(this, program);
	}

	void setCurrentSymbol(Symbol symbol) {
		referenceKeyModel.setCurrentSymbol(symbol);
	}

	void symbolChanged(Symbol symbol) {
		if (isVisible()) {
			referenceKeyModel.symbolChanged(symbol);
		}
	}

	void symbolRemoved(Symbol symbol) {
		if (isVisible()) {
			referenceKeyModel.symbolRemoved(symbol);
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
