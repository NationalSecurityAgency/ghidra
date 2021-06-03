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
package ghidra.app.plugin.core.blockmodel;

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.TreeMap;

import docking.options.editor.StringWithChoicesEditor;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.BlockModelServiceListener;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.NotFoundException;

/** 
 * Provides a service for tracking the selected basic/subroutine block models for a tool.
 * Methods are provided for obtaining an instance of the active or arbitrary block model.
 * A new model instance is always provided since the internal cache will quickly become 
 * stale based upon program changes.  The current model implementations do not handle 
 * program changes which would invalidate the cached blocks stored within the model.
 * 
 * A single basic/sub model list is maintained since it is possible that some uses
 * may utilize either type of block model.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Provides the block model service",
	description = "This plugin provides registration and distribution of basic-block "
			+ "and subroutine models via the block model service.",
	servicesProvided = { BlockModelService.class }
)
//@formatter:on
public class BlockModelServicePlugin extends ProgramPlugin
		implements BlockModelService, OptionsChangeListener {

	private static final String SUB_OPTION = "Subroutine Block Model";

	private TreeMap<String, BlockModelInfo> basicModelsByName =
		new TreeMap<>();
	private TreeMap<String, BlockModelInfo> subroutineModelsByName =
		new TreeMap<>();
	private BlockModelInfo activeBasicModel;
	private BlockModelInfo activeSubroutineModel;

	private ToolOptions options;
	private String selectedSubroutineModelName;
	private String preferedSubroutineModeName;

	private boolean modelUpdateInProgress = false;

	private WeakSet<BlockModelServiceListener> listenerList =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private StringWithChoicesEditor editor;

	public BlockModelServicePlugin(PluginTool tool) {

		super(tool, false, false);

		// Add standard simple block model
		BlockModelInfo info = new BlockModelInfo(SimpleBlockModel.NAME, SimpleBlockModel.class);
		basicModelsByName.put(SimpleBlockModel.NAME, info);
		activeBasicModel = info;

		// Add standard multi-entry subroutine model
		info = new BlockModelInfo(MultEntSubModel.NAME, MultEntSubModel.class);
		subroutineModelsByName.put(MultEntSubModel.NAME, info);
		activeSubroutineModel = info;

		// Add special subroutine models
		info =
			new BlockModelInfo(OverlapCodeSubModel.OVERLAP_MODEL_NAME, OverlapCodeSubModel.class);
		subroutineModelsByName.put(OverlapCodeSubModel.OVERLAP_MODEL_NAME, info);
		info = new BlockModelInfo(IsolatedEntrySubModel.ISOLATED_MODEL_NAME,
			IsolatedEntrySubModel.class);
		subroutineModelsByName.put(IsolatedEntrySubModel.ISOLATED_MODEL_NAME, info);
		info =
			new BlockModelInfo(OverlapCodeSubModel.OVERLAP_MODEL_NAME, PartitionCodeSubModel.class);
		subroutineModelsByName.put(PartitionCodeSubModel.NAME, info);

		String[] availableModelNames = getAvailableModelNames(SUBROUTINE_MODEL);
		selectedSubroutineModelName = availableModelNames[0];

		// Install model selection option in Tool panel
		options = tool.getOptions(ToolConstants.TOOL_OPTIONS);
		editor = new StringWithChoicesEditor(availableModelNames);
		options.registerOption(SUB_OPTION, OptionType.STRING_TYPE, selectedSubroutineModelName,
			null, "The default subroutine model used when creating call graphs.", editor);
		setPreferedModel(options);
		updateModelOptions();
		options.addOptionsChangeListener(this);

		// Set active subroutine block model
//        activeSubroutineModelFactory = (CodeBlockModel) subroutineModelsByName.get(subroutineModelList.getSelectedValue());
	}

	/**
	 * Handle an option change
	 * @param newOptions options object containing the property that changed
	 * @param optionName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 */
	@Override
	public void optionsChanged(ToolOptions newOptions, String optionName, Object oldValue,
			Object newValue) {
		if (!modelUpdateInProgress && SUB_OPTION.equals(optionName)) {
			setPreferedModel(newOptions);
		}
	}

	private void setPreferedModel(Options options) {

		// Set active subroutine block model using option selection
		preferedSubroutineModeName = options.getString(SUB_OPTION, selectedSubroutineModelName);
		if (activeSubroutineModel == null ||
			!activeSubroutineModel.modelName.equals(preferedSubroutineModeName)) {
			activeSubroutineModel = subroutineModelsByName.get(preferedSubroutineModeName);
		}
	}

	private void updateModelOptions() {

		String[] availableModelNames = getAvailableModelNames(SUBROUTINE_MODEL);
		try {
			if (subroutineModelsByName.containsKey(preferedSubroutineModeName)) {
				activeSubroutineModel = subroutineModelsByName.get(preferedSubroutineModeName);
			}
			if (activeSubroutineModel != null &&
				subroutineModelsByName.containsKey(activeSubroutineModel.modelName)) {
				selectedSubroutineModelName = activeSubroutineModel.modelName;
			}
			else {
				activeSubroutineModel = subroutineModelsByName.get(selectedSubroutineModelName);
			}
		}
		catch (IllegalArgumentException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}

		modelUpdateInProgress = true;
		try {
			editor.setChoices(availableModelNames);
			options.setString(SUB_OPTION, selectedSubroutineModelName);
		}
		finally {
			modelUpdateInProgress = false;
		}

	}

	/**
	 * @see ghidra.app.services.BlockModelService#registerModel(java.lang.Class, java.lang.String)
	 */
	@Override
	public void registerModel(Class<? extends CodeBlockModel> modelClass, String modelName) {
		if (SubroutineBlockModel.class.isAssignableFrom(modelClass)) {
			if (!subroutineModelsByName.containsKey(modelName)) {
				subroutineModelsByName.put(modelName, new BlockModelInfo(modelName, modelClass));
				updateModelOptions();
				fireModelAdded(modelName, SUBROUTINE_MODEL);
			}
		}
		else if (!basicModelsByName.containsKey(modelName)) {
			basicModelsByName.put(modelName, new BlockModelInfo(modelName, modelClass));
			fireModelAdded(modelName, BASIC_MODEL);
		}
	}

	/**
	 * @see ghidra.app.services.BlockModelService#unregisterModel(java.lang.Class)
	 */
	@Override
	public void unregisterModel(Class<? extends CodeBlockModel> modelClass) {
		if (SubroutineBlockModel.class.isAssignableFrom(modelClass)) {
			BlockModelInfo info = findSubroutineModel(modelClass);
			if (info != null) {
				subroutineModelsByName.remove(info.modelName);
				updateModelOptions();
				fireModelRemoved(info.modelName, SUBROUTINE_MODEL);
			}
		}
		else {
			BlockModelInfo info = findBasicModel(modelClass);
			if (info != null) {
				subroutineModelsByName.remove(info.modelName);
				updateModelOptions();
				fireModelRemoved(info.modelName, BASIC_MODEL);
			}
		}
	}

	private BlockModelInfo findSubroutineModel(Class<? extends CodeBlockModel> modelClass) {
		for (BlockModelInfo info : subroutineModelsByName.values()) {
			if (info.modelClass == modelClass) {
				return info;
			}
		}
		return null;
	}

	private BlockModelInfo findBasicModel(Class<? extends CodeBlockModel> modelClass) {
		for (BlockModelInfo info : basicModelsByName.values()) {
			if (info.modelClass == modelClass) {
				return info;
			}
		}
		return null;
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveBlockModel()
	 */
	@Override
	public CodeBlockModel getActiveBlockModel() {
		if (currentProgram == null) {
			return null;
		}
		return getModelInstance(activeBasicModel.modelClass, currentProgram, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveBlockModel(boolean)
	 */
	@Override
	public CodeBlockModel getActiveBlockModel(boolean includeExternals) {
		if (currentProgram == null) {
			return null;
		}
		return getModelInstance(activeBasicModel.modelClass, currentProgram, includeExternals);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveBlockModel(ghidra.program.model.listing.Program)
	 */
	@Override
	public CodeBlockModel getActiveBlockModel(Program program) {
		if (program == null) {
			return null;
		}
		return getModelInstance(activeBasicModel.modelClass, program, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveBlockModel(ghidra.program.model.listing.Program, boolean)
	 */
	@Override
	public CodeBlockModel getActiveBlockModel(Program program, boolean includeExternals) {
		if (program == null) {
			return null;
		}
		return getModelInstance(activeBasicModel.modelClass, program, includeExternals);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveSubroutineModel()
	 */
	@Override
	public CodeBlockModel getActiveSubroutineModel() {
		if (currentProgram == null) {
			return null;
		}
		return getModelInstance(activeSubroutineModel.modelClass, currentProgram, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveSubroutineModel(boolean)
	 */
	@Override
	public CodeBlockModel getActiveSubroutineModel(boolean includeExternals) {
		if (currentProgram == null) {
			return null;
		}
		return getModelInstance(activeSubroutineModel.modelClass, currentProgram, includeExternals);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveSubroutineModel(ghidra.program.model.listing.Program)
	 */
	@Override
	public CodeBlockModel getActiveSubroutineModel(Program program) {
		if (program == null) {
			return null;
		}
		return getModelInstance(activeSubroutineModel.modelClass, program, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveSubroutineModel(ghidra.program.model.listing.Program, boolean)
	 */
	@Override
	public CodeBlockModel getActiveSubroutineModel(Program program, boolean includeExternals) {
		if (program == null) {
			return null;
		}
		return getModelInstance(activeSubroutineModel.modelClass, program, includeExternals);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveBlockModelName()
	 */
	@Override
	public String getActiveBlockModelName() {
		return activeBasicModel.modelName;
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getActiveSubroutineModelName()
	 */
	@Override
	public String getActiveSubroutineModelName() {
		return activeSubroutineModel.modelName;
	}

	private CodeBlockModel getModelInstance(Class<? extends CodeBlockModel> modelClass,
			Program program, boolean includeExternals) {
		try {
			Constructor<? extends CodeBlockModel> c =
				modelClass.getConstructor(new Class[] { Program.class, boolean.class });
			return c.newInstance(new Object[] { program, Boolean.valueOf(includeExternals) });
		}
		catch (Exception e) {
		}

		try {
			Constructor<? extends CodeBlockModel> c =
				modelClass.getConstructor(new Class[] { Program.class });
			return c.newInstance(new Object[] { program });
		}
		catch (Exception e) {
		}

		Msg.error(this, "ERROR! Failed to instantiate model: " + modelClass.getName());

		return null;
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getNewModelByName(java.lang.String)
	 */
	@Override
	public CodeBlockModel getNewModelByName(String modelName) throws NotFoundException {
		return getNewModelByName(modelName, currentProgram, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getNewModelByName(java.lang.String, boolean)
	 */
	@Override
	public CodeBlockModel getNewModelByName(String modelName, boolean includeExtenernals)
			throws NotFoundException {
		return getNewModelByName(modelName, currentProgram, includeExtenernals);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getNewModelByName(java.lang.String, ghidra.program.model.listing.Program)
	 */
	@Override
	public CodeBlockModel getNewModelByName(String modelName, Program program)
			throws NotFoundException {
		return getNewModelByName(modelName, program, false);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getNewModelByName(java.lang.String, ghidra.program.model.listing.Program, boolean)
	 */
	@Override
	public CodeBlockModel getNewModelByName(String modelName, Program program,
			boolean includeExternals) throws NotFoundException {
		if (program == null) {
			return null;
		}
		BlockModelInfo info = basicModelsByName.get(modelName);
		if (info != null) {
			return getModelInstance(info.modelClass, program, includeExternals);
		}
		info = subroutineModelsByName.get(modelName);
		if (info != null) {
			return getModelInstance(info.modelClass, program, includeExternals);
		}
		throw new NotFoundException("Block model not found: " + modelName);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#getAvailableModelNames(int)
	 */
	@Override
	public String[] getAvailableModelNames(int modelType) {

		TreeMap<String, BlockModelInfo> models =
			(modelType == BASIC_MODEL) ? basicModelsByName : subroutineModelsByName;
		String defaultModelName =
			(modelType == BASIC_MODEL) ? DEFAULT_BLOCK_MODEL_NAME : DEFAULT_SUBROUTINE_MODEL_NAME;

		ArrayList<String> list = new ArrayList<>();
		for (String modelName : models.keySet()) {
			if (modelName.equals(defaultModelName)) {
				list.add(0, modelName);
			}
			else {
				list.add(modelName);
			}
		}

		String[] modelNames = new String[list.size()];
		list.toArray(modelNames);
		return modelNames;
	}

	/**
	 * @see ghidra.app.services.BlockModelService#addListener(ghidra.app.services.BlockModelServiceListener)
	 */
	@Override
	public void addListener(BlockModelServiceListener listener) {
		listenerList.add(listener);
	}

	/**
	 * @see ghidra.app.services.BlockModelService#removeListener(ghidra.app.services.BlockModelServiceListener)
	 */
	@Override
	public void removeListener(BlockModelServiceListener listener) {
		listenerList.remove(listener);
	}

	private void fireModelAdded(String modelName, int modelType) {
		for (BlockModelServiceListener listener : listenerList) {
			listener.modelAdded(modelName, modelType);
		}
	}

	private void fireModelRemoved(String modelName, int modelType) {
		for (BlockModelServiceListener listener : listenerList) {
			listener.modelRemoved(modelName, modelType);
		}
	}

	private static class BlockModelInfo {
		String modelName;
		Class<? extends CodeBlockModel> modelClass;

		BlockModelInfo(String modelName, Class<? extends CodeBlockModel> modelClass) {
			this.modelName = modelName;
			this.modelClass = modelClass;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof BlockModelInfo) {
				return modelName == ((BlockModelInfo) obj).modelName;
			}
			return false;
		}

		@Override
		public int hashCode() {
			return modelName.hashCode();
		}
	}

}
