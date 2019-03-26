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
package ghidra.app.plugin.core.decompile.actions;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.function.editor.*;
import ghidra.app.services.DataTypeManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;

public class SpecifyCPrototypeAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;
	//private FunctionSignature signature = null;
	//private String callingConventionName = null;

	public SpecifyCPrototypeAction(String owner, PluginTool tool, DecompilerController controller) {
		super("Edit Function Signature", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Edit Function Signature" }, "Decompile"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		return getFunction() != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		Function function = getFunction();
		DataTypeManagerService service = tool.getService(DataTypeManagerService.class);

		FunctionEditorModel model = new FunctionEditorModel(service, function);

		HighFunction hf = controller.getHighFunction();
		FunctionPrototype functionPrototype = hf.getFunctionPrototype();

		// If editing the decompiled function (i.e., not a subfunction) and function
		// is not fully locked update the model to reflect the decompiled results
		if (function.getEntryPoint().equals(hf.getFunction().getEntryPoint())) {
			if (function.getSignatureSource() == SourceType.DEFAULT) {
				model.setUseCustomizeStorage(false);
				model.setCallingConventionName(functionPrototype.getModelName());
				model.setFunctionData(buildSignature(hf));
				verifyDynamicEditorModel(hf, model);
			}
			else if (function.getReturnType() == DataType.DEFAULT) {
				model.setFormalReturnType(functionPrototype.getReturnType());
				if (model.canCustomizeStorage()) {
					model.setReturnStorage(functionPrototype.getReturnStorage());
				}
			}
		}

		// make the model think it is not changed, so if the user doesn't change anything, 
		// we don't save the changes made above.
		model.setModelChanged(false);

		FunctionEditorDialog dialog = new FunctionEditorDialog(model);
		tool.showDialog(dialog, context.getComponentProvider());
	}

	/**
	 * Verify and adjust function editor model using dynamic storage to reflect current state of 
	 * decompiled results.  It may be necessary to switch model to use custom storage.
	 * @param hf decompiled high function
	 * @param model function editor model
	 */
	private void verifyDynamicEditorModel(HighFunction hf, FunctionEditorModel model) {

		FunctionPrototype functionPrototype = hf.getFunctionPrototype();
		int decompParamCnt = functionPrototype.getNumParams();

		List<ParamInfo> parameters = model.getParameters();
		int modelParamCnt = parameters.size();

		// growth accounts for auto param injection
		int autoParamCnt = modelParamCnt - decompParamCnt;

		// make sure decomp params account for injected auto params
		boolean useCustom = (decompParamCnt < autoParamCnt);

		for (int i = 0; i < autoParamCnt && !useCustom; i++) {
			if (i >= decompParamCnt) {
				useCustom = true;
			}
			else {
				VariableStorage modelParamStorage = parameters.get(i).getStorage();
				VariableStorage decompParamStorage = functionPrototype.getParam(i).getStorage();
				if (!modelParamStorage.equals(decompParamStorage)) {
					useCustom = true;
				}
			}
		}

		if (!useCustom) {
			// remove original params which replicate auto params
			for (int i = 0; i < autoParamCnt; i++) {
				model.setSelectedParameterRow(new int[] { autoParamCnt });
				model.removeParameters();
			}

			// verify remaining parameter storage
			for (int i = autoParamCnt; i < decompParamCnt; i++) {
				VariableStorage modelParamStorage = parameters.get(i).getStorage();
				VariableStorage decompParamStorage = functionPrototype.getParam(i).getStorage();
				if (!modelParamStorage.equals(decompParamStorage)) {
					useCustom = true;
					break;
				}
			}
		}

		// TODO: return storage not currently returned from Decompiler

		if (useCustom) {
			// Force custom storage
			model.setUseCustomizeStorage(true);
			model.setFunctionData(buildSignature(hf));
			model.setReturnStorage(functionPrototype.getReturnStorage());
			parameters = model.getParameters();
			for (int i = 0; i < decompParamCnt; i++) {
				model.setParameterStorage(parameters.get(i),
					functionPrototype.getParam(i).getStorage());
			}
		}
	}

	private FunctionDefinitionDataType buildSignature(HighFunction hf) {
		// try to look up the function that is at the current cursor location
		//   If there isn't one, just use the function we are in.

		Function func = hf.getFunction();
		FunctionDefinitionDataType fsig = new FunctionDefinitionDataType(CategoryPath.ROOT,
			func.getName(), func.getProgram().getDataTypeManager());
		FunctionPrototype functionPrototype = hf.getFunctionPrototype();

		int np = hf.getLocalSymbolMap().getNumParams();
		fsig.setReturnType(functionPrototype.getReturnType());

		ParameterDefinition[] args = new ParameterDefinitionImpl[np];
		for (int i = 0; i < np; i++) {
			HighParam parm = hf.getLocalSymbolMap().getParam(i);
			args[i] = new ParameterDefinitionImpl(parm.getName(), parm.getDataType(), null);
		}
		fsig.setArguments(args);
		fsig.setVarArgs(functionPrototype.isVarArg());
		return fsig;
	}

	/**
	 * @return the currently highlighted function or the currently decompiled
	 *         function if there isn't one.
	 */
	synchronized Function getFunction() {
		// try to look up the function that is at the current cursor location
		//   If there isn't one, just use the function we are in.
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		Function function = controller.getFunction();
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			Function tokenFunction = DecompilerUtils.getFunction(controller.getProgram(),
				(ClangFuncNameToken) tokenAtCursor);
			if (tokenFunction != null) {
				function = tokenFunction;
			}
		}
		return function;
	}
}
