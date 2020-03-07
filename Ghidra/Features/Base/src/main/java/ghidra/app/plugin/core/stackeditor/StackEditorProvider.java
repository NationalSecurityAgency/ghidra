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
package ghidra.app.plugin.core.stackeditor;

import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;

/**
 * Editor for a Function Stack.
 */
public class StackEditorProvider extends CompositeEditorProvider implements DomainObjectListener {

	private Program program;
	private Function function;
	private StackEditorModel stackModel;

	public StackEditorProvider(Plugin plugin, Function function) {
		super(plugin);
		this.program = function.getProgram();
		this.function = function;
		program.addListener(this);
		editorModel = new StackEditorModel(this);
		stackModel = (StackEditorModel) editorModel;
		stackModel.load(function);

		initializeActions();
		editorPanel = new StackEditorPanel(program, stackModel, this);
		setTitle(getName() + " - " + getProviderSubTitle(function));
		plugin.getTool().addComponentProvider(this, true);

		addActionsToTool();
		editorPanel.getTable().requestFocus();
	}

	@Override
	public void dispose() {
		program.removeListener(this);
		super.dispose();
	}

	static String getProviderSubTitle(Function function) {
		Program pgm = function.getProgram();
		return function.getName() + " (" + pgm.getDomainFile().getName() + ")";
	}

	@Override
	protected Plugin getPlugin() {
		return plugin;
	}

	@Override
	public String getName() {
		return "Stack Editor";
	}

	@Override
	public String getHelpName() {
		return "Stack_Editor";
	}

	@Override
	public String getHelpTopic() {
		return "StackEditor";
	}

	@Override
	protected CompositeEditorTableAction[] createActions() {
		//@formatter:off
		return new CompositeEditorTableAction[] { 
			new ApplyAction(this), 
			new ClearAction(this),
			new DeleteAction(this), 
			new PointerAction(this), 
			new ArrayAction(this),
			new ShowComponentPathAction(this), 
			new EditComponentAction(this),
			new EditFieldAction(this), 
			new HexNumbersAction(this) 
		};
		//@formatter:on
	}

	/**
	 * Gets the function name for the function stack frame being edited. 
	 * @return the name
	 */
	String getStackName() {
		return stackModel.getEditorStack().getDisplayName();
	}

	/**
	 * Gets the function for the function stack frame being edited. 
	 * @return the function
	 */
	Function getFunction() {
		StackFrameDataType editorStack = stackModel.getEditorStack();
		if (editorStack == null) {
			return null;
		}
		return editorStack.getFunction();
	}

	@Override
	public boolean isEditing(DataTypePath functionPath) {
		return getDtPath().equals(functionPath);
	}

	/**
	 * Gets the program associated with the stack frame being edited.
	 */
	protected Program getProgram() {
		return program;
	}

	@Override
	protected CompositeEditorModel getModel() {
		return stackModel;
	}

	@Override
	protected CompositeEditorTableAction[] getActions() {
		return actionMgr.getAllActions();
	}

	@Override
	public void domainObjectRestored(DataTypeManagerDomainObject domainObject) {
		refreshName();
		editorPanel.domainObjectRestored(domainObject);
	}

	private void refreshName() {
		StackFrameDataType origDt = (StackFrameDataType) stackModel.getOriginalComposite();
		StackFrameDataType viewDt = stackModel.getViewComposite();
		String oldName = origDt.getName();
		String newName = function.getName();
		if (oldName.equals(newName)) {
			return;
		}

		setTitle("Stack Editor: " + newName);
		try {
			origDt.setName(newName);
			if (viewDt.getName().equals(oldName)) {
				viewDt.setName(newName);
			}
		}
		catch (InvalidNameException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		CategoryPath oldCategoryPath = origDt.getCategoryPath();
		DataTypePath oldDtPath = new DataTypePath(oldCategoryPath, oldName);
		DataTypePath newDtPath = new DataTypePath(oldCategoryPath, newName);
		stackModel.dataTypeRenamed(stackModel.getOriginalDataTypeManager(), oldDtPath, newDtPath);
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (!isVisible()) {
			return;
		}

		int recordCount = event.numRecords();
		for (int i = 0; i < recordCount; i++) {
			DomainObjectChangeRecord rec = event.getChangeRecord(i);
			int eventType = rec.getEventType();
			switch (eventType) {
				case DomainObject.DO_OBJECT_RESTORED:
					Object source = event.getSource();
					if (source instanceof Program) {
						Program restoredProgram = (Program) source;
						domainObjectRestored(restoredProgram);
					}
					return;
				case ChangeManager.DOCR_FUNCTION_REMOVED:
					Function func = (Function) ((ProgramChangeRecord) rec).getObject();
					if (func == function) {
						this.dispose();
						tool.setStatusInfo("Stack Editor was closed for " + getName());
					}
					return;
				case ChangeManager.DOCR_SYMBOL_RENAMED:
				case ChangeManager.DOCR_SYMBOL_DATA_CHANGED:
					Symbol sym = (Symbol) ((ProgramChangeRecord) rec).getObject();
					SymbolType symType = sym.getSymbolType();
					if (symType == SymbolType.LABEL) {
						if (sym.isPrimary() && sym.getAddress().equals(function.getEntryPoint())) {
							refreshName();
						}
					}
					else if (inCurrentFunction(rec)) {
						reloadFunction();
					}
					break;
				case ChangeManager.DOCR_FUNCTION_CHANGED:
				case ChangeManager.DOCR_SYMBOL_ADDED:
				case ChangeManager.DOCR_SYMBOL_REMOVED:
				case ChangeManager.DOCR_SYMBOL_ADDRESS_CHANGED:
					if (inCurrentFunction(rec)) {
						reloadFunction();
					}
					break;
				case ChangeManager.DOCR_SYMBOL_SET_AS_PRIMARY:
					sym = (Symbol) ((ProgramChangeRecord) rec).getObject();
					symType = sym.getSymbolType();
					if (symType == SymbolType.LABEL &&
						sym.getAddress().equals(function.getEntryPoint())) {
						refreshName();
					}
			}
		}
	}

	private void reloadFunction() {
		if (!stackModel.hasChanges()) {
			stackModel.load(function);
		}
		else {
			stackModel.stackChangedExcternally(true);
			editorPanel.setStatus("Stack may have been changed externally--data may be stale.");
		}
	}

	private boolean inCurrentFunction(DomainObjectChangeRecord record) {
		if (!(record instanceof ProgramChangeRecord)) {
			return false;
		}

		if (function == null) {
			return false; // not sure if this can happen
		}

		ProgramChangeRecord programChangeRecord = (ProgramChangeRecord) record;
		Object affectedValue = programChangeRecord.getObject();
		if (affectedValue instanceof Symbol) {
			Address address = ((Symbol) affectedValue).getAddress();
			if (address.isVariableAddress()) {
				Symbol s = (Symbol) affectedValue;
				return s.getParentNamespace() == function;
			}
		}
		else if (affectedValue instanceof Function) {
			Address changedEntry = ((Function) affectedValue).getEntryPoint();
			if (changedEntry.equals(function.getEntryPoint())) {
				return true;
			}
		}

		return false;
	}
}
