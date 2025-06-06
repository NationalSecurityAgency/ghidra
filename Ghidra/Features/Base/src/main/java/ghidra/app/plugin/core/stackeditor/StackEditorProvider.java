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

import java.awt.event.MouseEvent;

import docking.ActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.task.SwingUpdateManager;

/**
 * Editor for a Function Stack.
 */
public class StackEditorProvider
		extends CompositeEditorProvider<StackFrameDataType, StackEditorModel>
		implements DomainObjectListener {

	private Program program;
	private Function function;
	private StackEditorModel stackModel;

	boolean scheduleRefreshName = false;
	boolean scheduleReload = false;

	/**
	 * Delay model update caused by Program change events.
	 */
	SwingUpdateManager delayedUpdateMgr = new SwingUpdateManager(200, 200, () -> {
		try {
			if (function.isDeleted()) {
				stackModel.functionChanged(false);
				return;
			}
			if (scheduleRefreshName) {
				updateTitle();
			}
			if (scheduleReload) {
				stackModel.functionChanged(false);
			}
		}
		finally {
			scheduleRefreshName = false;
			scheduleReload = false;
		}
	});

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
		updateTitle();
		plugin.getTool().addComponentProvider(this, true);

		addActionsToTool();
		editorPanel.getTable().requestFocus();
	}

	@Override
	protected void updateTitle() {
		setTabText(function.getName());
		setTitle(getName() + " - " + getProviderSubTitle(function));
	}

	@Override
	public void dispose() {
		delayedUpdateMgr.dispose();
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
	protected String getDisplayName() {
		return "stack frame: " + function.getName();
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

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		return new ProgramActionContext(this, program);
	}

	String getStackName() {
		return stackModel.getEditorStack().getDisplayName();
	}

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

	protected Program getProgram() {
		return program;
	}

	@Override
	protected StackEditorModel getModel() {
		return stackModel;
	}

	@Override
	protected CompositeEditorTableAction[] getActions() {
		return actionMgr.getAllActions();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent event) {
		if (!isVisible()) {
			return;
		}

		int recordCount = event.numRecords();
		for (int i = 0; i < recordCount; i++) {

			DomainObjectChangeRecord rec = event.getChangeRecord(i);
			EventType eventType = rec.getEventType();

			// NOTE: RESTORED event can be ignored here since the model will be notified 
			// of restored datatype manager via the CompositeViewerModel's 
			// DataTypeManagerChangeListener restored method.

			if (eventType == DomainObjectEvent.FILE_CHANGED) {
				scheduleRefreshName = true;
				delayedUpdateMgr.updateLater();
				continue;
			}
			if (eventType instanceof ProgramEvent type) {
				switch (type) {
					case FUNCTION_REMOVED:
						Function func = (Function) ((ProgramChangeRecord) rec).getObject();
						if (func == function) {
							// Close the Editor.
							tool.setStatusInfo("Stack Editor was closed for " + getName());
							dispose();
							return;
						}
						break;
					case SYMBOL_RENAMED:
					case SYMBOL_DATA_CHANGED:
						Symbol sym = (Symbol) ((ProgramChangeRecord) rec).getObject();
						if (sym.isPrimary() && sym.getAddress().equals(function.getEntryPoint())) {
							scheduleRefreshName = true;
							delayedUpdateMgr.updateLater();
						}
						else if (inCurrentFunction(rec)) {
							scheduleReload = true;
							delayedUpdateMgr.updateLater();
						}
						break;
					case FUNCTION_CHANGED:
					case SYMBOL_ADDED:
					case SYMBOL_REMOVED:
					case SYMBOL_ADDRESS_CHANGED:
						if (inCurrentFunction(rec)) {
							scheduleReload = true;
							delayedUpdateMgr.updateLater();
						}
						break;
					case SYMBOL_PRIMARY_STATE_CHANGED:
						sym = (Symbol) ((ProgramChangeRecord) rec).getNewValue();
						if (sym.getAddress().equals(function.getEntryPoint())) {
							scheduleRefreshName = true;
							delayedUpdateMgr.updateLater();
						}
						break;
					default:
				}
			}
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
