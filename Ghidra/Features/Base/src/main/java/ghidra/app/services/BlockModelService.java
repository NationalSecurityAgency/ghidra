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
package ghidra.app.services;

import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.NotFoundException;

/**
 * Service for providing block models.
 */
@ServiceInfo(description = "Provides registration and distribution of basic-block and subroutine models.")
public interface BlockModelService {

	/**
	 * Type for a simple block model.
	 * @see ghidra.program.model.block.SimpleBlockModel
	 */
	public static final int BASIC_MODEL = 1;

	/**
	 * Type for a subroutine block model.
	 */
	public static final int SUBROUTINE_MODEL = 2;

	/**
	 * Name of the implementation for a Simple block model.
	 */
	public static final String SIMPLE_BLOCK_MODEL_NAME = SimpleBlockModel.NAME;

	/**
	 * Name of the implementation for a subroutine with multiple entry points.
	 */
	public static final String MULTI_ENTRY_SUBROUTINE_MODEL_NAME = MultEntSubModel.NAME;

	/**
	 * Name of the implementation for a subroutine that has a unique entry
	 * point, which may share code with other subroutines.
	 */
	public static final String ISOLATED_ENTRY_SUBROUTINE_MODEL_NAME = IsolatedEntrySubModel.ISOLATED_MODEL_NAME;

	/**
	 * Name of the implementation for an overlapped subroutine model.
	 */
	public static final String OVERLAPPED_SUBROUTINE_MODEL_NAME = OverlapCodeSubModel.OVERLAP_MODEL_NAME;

	/**
	 * Name of the implementation for a subroutine that does not share code
	 * with other subroutines and may have one or more entry points.
	 */
	public static final String PARTITIONED_SUBROUTINE_MODEL_NAME = PartitionCodeSubModel.NAME;

	/**
	 * Default basic block model (Simple Block Model)
	 */
	public static final String DEFAULT_BLOCK_MODEL_NAME = SIMPLE_BLOCK_MODEL_NAME;

	/**
	 * Default subroutine model (M-Model)
	 */
	public static final String DEFAULT_SUBROUTINE_MODEL_NAME = MULTI_ENTRY_SUBROUTINE_MODEL_NAME;


	/**
	 * Register a new model.
	 * @param modelClass code block model class.
	 * Subroutine models must implement the SubroutineBlockMode interface - all other models
	 * are assumed to be basic block models.
	 * @param modelName name of model
	 */
	public void registerModel(Class<? extends CodeBlockModel> modelClass, String modelName);

	/**
	 * Deregister a model.
	 * @param modelClass code block model class.
	 */
	public void unregisterModel(Class<? extends CodeBlockModel> modelClass);

	/**
	 * Get new instance of the active Basic Block model for the current program.
	 * @return new Basic Block model instance or null if program is not open.
	 * @deprecated use getActiveBlockModel(Program) instead
	 */
	@Deprecated
	public CodeBlockModel getActiveBlockModel();

	/**
	 * Get new instance of the active Basic Block model for the current program.
	 * @param includeExternals externals are included if true
	 * @return new Basic Block model instance or null if program is not open.
	 * @deprecated use getActiveBlockModel(Program, boolean) instead
	 */
	@Deprecated
	public CodeBlockModel getActiveBlockModel(boolean includeExternals);

	/**
	 * Get new instance of the active Basic Block model.
	 * @param program program to associate with the block model
	 * @return new Basic Block model instance or null if program is null
	 */
	public CodeBlockModel getActiveBlockModel(Program program);

	/**
	 * Get new instance of the active Basic Block model.
	 * @param program program to associate with the block model
	 * @param includeExternals externals are included if true
	 * @return new Basic Block model instance or null if program is null
	 */
	public CodeBlockModel getActiveBlockModel(Program program, boolean includeExternals);

	/**
	 * Get the name of the active Basic Block model.
	 * @return active block model name
	 */
	public String getActiveBlockModelName();

	/**
	 * Get new instance of the active Subroutine Block model for the current program.
	 * @return new Subroutine Block model instance or null if program is not open
	 * @deprecated use getActiveSubroutineModel(Program) instead
	 */
	@Deprecated
	public CodeBlockModel getActiveSubroutineModel();

	/**
	 * Get new instance of the active Subroutine Block model for the current program.
	 * @param includeExternals externals are included if true
	 * @return new Subroutine Block model instance or null if program is not open
	 * @deprecated use getActiveSubroutineModel(Program) instead
	 */
	@Deprecated
	public CodeBlockModel getActiveSubroutineModel(boolean includeExternals);

	/**
	 * Get new instance of the active Subroutine Block model.
	 * @param program program associated with the block model.
	 * @return new Subroutine Block model instance or null if program is null
	 */
	public CodeBlockModel getActiveSubroutineModel(Program program);

	/**
	 * Get new instance of the active Subroutine Block model.
	 * @param program program associated with the block model.
	 * @param includeExternals externals are included if true
	 * @return new Subroutine Block model instance or null if program is null
	 */
	public CodeBlockModel getActiveSubroutineModel(Program program, boolean includeExternals);

	/**
	 * Get the name of the active Subroutine model.
	 * @return active subroutine model name
	 */
	public String getActiveSubroutineModelName();

	/**
	 * Get new instance of the specified block model.
	 * @param modelName name of registered block model
	 * @return new model instance or null if program is not open.
	 * @throws NotFoundException if specified model is not registered
	 * @deprecated use getNewModelByName(String, Program) instead
	 */
	@Deprecated
	public CodeBlockModel getNewModelByName(String modelName)
			throws NotFoundException;

	/**
	 * Get new instance of the specified block model.
	 * @param modelName name of registered block model
	 * @param includeExternals externals are included if true
	 * @return new model instance or null if program is not open.
	 * @throws NotFoundException if specified model is not registered
	 * @deprecated use getNewModelByName(String, Program, boolean) instead
	 */
	@Deprecated
	public CodeBlockModel getNewModelByName(String modelName, boolean includeExternals)
			throws NotFoundException;

	/**
	 * Get new instance of the specified block model.
	 * @param modelName name of registered block model
	 * @param program program associated with the model
	 * @return new model instance or null if program is null
	 * @throws NotFoundException if specified model is not registered
	 */
	public CodeBlockModel getNewModelByName(String modelName, Program program)
			throws NotFoundException;

	/**
	 * Get new instance of the specified block model.
	 * @param modelName name of registered block model
	 * @param program program associated with the model
	 * @param includeExternals externals are included if true
	 * @return new model instance or null if program is null
	 * @throws NotFoundException if specified model is not registered
	 */
	public CodeBlockModel getNewModelByName(String modelName, Program program, boolean includeExternals)
			throws NotFoundException;

	/**
	 * Get list of registered block models of the specified type.
	 * A modelType of ANY_BLOCK will return all models registered.
	 * List ordering is based upon the registration order.
	 * It is important to recognize that the list of returned names
	 * could change as models are registered and unregistered.
	 * @param modelType type of model (ANY_MODEL, BASIC_MODEL or SUBROUTINE_MODEL)
	 * @return array of model names
	 */
	public String[] getAvailableModelNames(int modelType);

	/**
	 * Add service listener.
	 * @param listener listener to add
	 */
	public void addListener(BlockModelServiceListener listener);

	/**
	 * Remove service listener.
	 * @param listener to remove
	 */
	public void removeListener(BlockModelServiceListener listener);

}
