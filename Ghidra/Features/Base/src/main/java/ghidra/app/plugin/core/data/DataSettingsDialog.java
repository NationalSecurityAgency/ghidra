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
package ghidra.app.plugin.core.data;

import java.util.ArrayList;
import java.util.List;

import ghidra.docking.settings.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class DataSettingsDialog extends AbstractSettingsDialog {

	private ProgramSelection selection; // Only set for data selection mode
	private Data data; // null for selection use
	private Program program;
	private Settings sampleSelectionSettings; // used to obtain suggested string values for selection case

	/**
	 * Construct for data instance settings based upon selection
	 * @param program program which contains data selection
	 * @param sel data selection
	 * @throws CancelledException if operation cancelled
	 */
	public DataSettingsDialog(Program program, ProgramSelection sel) throws CancelledException {
		super("Common Settings for Selected Data", getCommonSettings(program, sel), null);
		this.program = program;
		this.selection = sel;
		setHelpLocation(new HelpLocation("DataPlugin", "Data_Settings_OnSelection"));
	}

	/**
	 * Construct for data instance settings (includes component instance) within a Program
	 * @param data data whose instance settings are to be modified
	 */
	public DataSettingsDialog(Data data) {
		super(constructTitle(data),
			getAllowedDataInstanceSettingsDefinitions(data.getDataType()), data);
		this.data = data;
		this.program = data.getProgram();

		// Set Help for use case - data vs. data-component
		Data pdata = data.getParent();
		if (pdata != null && (pdata.getBaseDataType() instanceof Composite)) {
			setHelpLocation(new HelpLocation("DataPlugin", "SettingsOnStructureComponents"));
		}
		else {
			setHelpLocation(new HelpLocation("DataPlugin", "Data_Settings"));
		}
	}

	static SettingsDefinition[] getAllowedDataInstanceSettingsDefinitions(DataType dt) {
		return SettingsDefinition.filterSettingsDefinitions(dt.getSettingsDefinitions(), def -> {
			return !(def instanceof TypeDefSettingsDefinition);
		});
	}

	private static String constructTitle(Data data) {
		StringBuffer buffy = new StringBuffer(
			DataTypeSettingsDialog.constructTitle(null, data.getDataType(), false));
		buffy.append(" at ");
		buffy.append(data.getMinAddress().toString());
		return buffy.toString();
	}

	@Override
	public void dispose() {
		program = null;
		super.dispose();
	}

	/**
	 * Build an array of SettingsDefinitions which are shared across
	 * all defined data constrained by an address set.
	 *
	 * The presence of an instruction will result in the selectionContainsInstruction
	 * flag being set.
	 *
	 */
	private static class CommonSettingsAccumulatorTask extends Task {

		Program program;
		ProgramSelection selection;

		SettingsDefinition[] defsArray = new SettingsDefinition[0];

		CommonSettingsAccumulatorTask(Program program, ProgramSelection selection) {
			super("Accumulating Data Settings", true, false, true);
			this.program = program;
			this.selection = selection;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			monitor.initialize(selection.getNumAddresses());
			InteriorSelection interiorSelection = selection.getInteriorSelection();
			if (interiorSelection != null) {
				accumulateInteriorSettingsDefinitions(interiorSelection, monitor);
			}
			else {
				accumulateDataSettingsDefinitions(monitor);
			}
		}

		private void accumulateDataSettingsDefinitions(TaskMonitor monitor)
				throws CancelledException {

			List<Class<? extends SettingsDefinition>> defClasses = new ArrayList<>();
			List<SettingsDefinition> defs = new ArrayList<>();

			Listing listing = program.getListing();
			DataIterator definedData = listing.getDefinedData(selection, true);
			if (!definedData.hasNext()) {
				return;
			}
			Data d = definedData.next();
			monitor.incrementProgress(d.getLength());
			for (SettingsDefinition def : d.getDataType().getSettingsDefinitions()) {
				if (def instanceof TypeDefSettingsDefinition) {
					continue; // default-use-only settings not supported
				}
				defs.add(def);
				defClasses.add(def.getClass());
			}

			while (!defClasses.isEmpty() && definedData.hasNext()) {
				monitor.checkCancelled();
				d = definedData.next();
				removeMissingDefinitions(defClasses, defs,
					d.getDataType().getSettingsDefinitions());
				monitor.incrementProgress(d.getLength());
			}
			defsArray = new SettingsDefinition[defs.size()];
			defs.toArray(defsArray);
		}

		private void accumulateInteriorSettingsDefinitions(InteriorSelection interiorSelection,
				TaskMonitor monitor) throws CancelledException {

			List<Class<? extends SettingsDefinition>> defClasses = null;
			List<SettingsDefinition> defs = null;

			int[] from = interiorSelection.getFrom().getComponentPath();
			int[] to = interiorSelection.getTo().getComponentPath();

			Data dataComp = DataPlugin.getDataUnit(program, selection.getMinAddress(), from);
			if (dataComp == null || from.length != to.length) {
				return;
			}
			Data parent = dataComp.getParent();
			int fromIndex = from[from.length - 1];
			int toIndex = to[to.length - 1];
			for (int i = fromIndex; i <= toIndex; i++) {
				monitor.checkCancelled();
				dataComp = parent.getComponent(i);
				if (dataComp == null) {
					break;
				}
				monitor.incrementProgress(dataComp.getLength());
				DataType dt = dataComp.getDataType();
				if (dt == DataType.DEFAULT) {
					continue;
				}
				SettingsDefinition[] settingsDefinitions = dt.getSettingsDefinitions();
				if (settingsDefinitions.length == 0) {
					return;
				}
				if (defClasses == null) {
					defClasses = new ArrayList<>();
					defs = new ArrayList<>();
					for (SettingsDefinition def : settingsDefinitions) {
						defs.add(def);
						defClasses.add(def.getClass());
					}
				}
				else {
					removeMissingDefinitions(defClasses, defs, settingsDefinitions);
				}
			}
			defsArray = new SettingsDefinition[defs.size()];
			defs.toArray(defsArray);
		}
	}

	private static SettingsDefinition[] getCommonSettings(Program program,
			ProgramSelection selection) throws CancelledException {
		CommonSettingsAccumulatorTask myTask = new CommonSettingsAccumulatorTask(program, selection);
		new TaskLauncher(myTask, null);
		if (myTask.isCancelled()) {
			throw new CancelledException();
		}
		return myTask.defsArray;
	}

	private static void removeMissingDefinitions(
			List<Class<? extends SettingsDefinition>> defClasses, List<SettingsDefinition> defs,
			SettingsDefinition[] checkDefs) {

		for (int i = defClasses.size() - 1; i >= 0; i--) {
			Class<? extends SettingsDefinition> c = defClasses.get(i);
			boolean found = false;
			for (SettingsDefinition checkDef : checkDefs) {
				if (c.isAssignableFrom(checkDef.getClass())) {
					found = true;
					break;
				}
			}
			if (!found) {
				defClasses.remove(i);
				defs.remove(i);
			}
		}
	}

	private static class ApplyCommonSettingsTask extends Task {

		DataSettingsDialog dlg;
		Program program;
		ProgramSelection selection;

		ApplyCommonSettingsTask(DataSettingsDialog dlg, Program program, ProgramSelection selection) {
			super("Applying Settings", true, false, true);
			this.dlg = dlg;
			this.program = program;
			this.selection = selection;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {

			monitor.initialize(selection.getNumAddresses());

			InteriorSelection interiorSelection = selection.getInteriorSelection();
			if (interiorSelection == null) {
				DataIterator definedData = program.getListing().getDefinedData(selection, true);
				while (definedData.hasNext()) {
					monitor.checkCancelled();
					Data d = definedData.next();
					applySettingsToData(dlg, d);
					monitor.incrementProgress(d.getLength());
				}
				return;
			}

			int[] from = interiorSelection.getFrom().getComponentPath();
			int[] to = interiorSelection.getTo().getComponentPath();

			Data dataComp = DataPlugin.getDataUnit(program, selection.getMinAddress(), from);
			if (dataComp == null) {
				return;
			}
			Data parent = dataComp.getParent();
			int fromIndex = from[from.length - 1];
			int toIndex = to[to.length - 1];

			monitor.initialize(toIndex - fromIndex + 1);
			for (int i = fromIndex; i <= toIndex; i++) {
				monitor.checkCancelled();
				dataComp = parent.getComponent(i);
				if (dataComp == null) {
					break;
				}
				monitor.incrementProgress(dataComp.getLength());
				DataType dt = dataComp.getDataType();
				if (dt == DataType.DEFAULT) {
					continue;
				}
				applySettingsToData(dlg, dataComp);
			}
		}

	}

	private static void applySettingsToData(DataSettingsDialog dlg, Data dataTarget) {
		Settings settings = dlg.getSettings();
		Settings defaultSettings = dlg.getDefaultSettings(); // may be null
		for (SettingsDefinition settingsDef : dlg.getSettingsDefinitions()) {
			if (dlg.selection != null && !settingsDef.hasValue(settings)) {
				continue; // No-Choice
			}

			if (settingsDef instanceof EnumSettingsDefinition) {
				EnumSettingsDefinition def = (EnumSettingsDefinition) settingsDef;

				int s = def.getChoice(settings);
				if (defaultSettings != null && s == def.getChoice(defaultSettings)) {
					def.clear(dataTarget);
				}
				else {
					def.setChoice(dataTarget, s);
				}
			}
			else if (settingsDef instanceof BooleanSettingsDefinition) {
				BooleanSettingsDefinition def = (BooleanSettingsDefinition) settingsDef;
				boolean s = def.getValue(settings);
				if (defaultSettings != null && s == def.getValue(defaultSettings)) {
					def.clear(dataTarget);
				}
				else {
					def.setValue(dataTarget, s);
				}
			}
			else if (settingsDef instanceof NumberSettingsDefinition) {
				NumberSettingsDefinition def = (NumberSettingsDefinition) settingsDef;
				long val = def.getValue(settings);
				if (defaultSettings != null && val == def.getValue(defaultSettings)) {
					def.clear(dataTarget);
				}
				else {
					def.setValue(dataTarget, val);
				}
			}
			else {
				throw new AssertException();
			}
		}
	}

	@Override
	protected String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
		if (!settingsDefinition.supportsSuggestedValues()) {
			return null;
		}
		if (data != null) {
			return settingsDefinition.getSuggestedValues(data);
		}
		if (sampleSelectionSettings == null) {
			DataIterator definedData = program.getListing().getDefinedData(selection, true);
			while (definedData.hasNext()) {
				sampleSelectionSettings = definedData.next();
				break;
			}
			if (sampleSelectionSettings == null) {
				return null;
			}
		}
		return settingsDefinition.getSuggestedValues(sampleSelectionSettings);
	}

	protected void applySettings() throws CancelledException {
		int txId = program.startTransaction(getTitle());
		try {
			if (selection != null) {
				ApplyCommonSettingsTask myTask =
					new ApplyCommonSettingsTask(this, program, selection);
				new TaskLauncher(myTask, null);
				if (myTask.isCancelled()) {
					throw new CancelledException();
				}
				return;
			}

			// assume single data settings
			applySettingsToData(this, data);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

}
