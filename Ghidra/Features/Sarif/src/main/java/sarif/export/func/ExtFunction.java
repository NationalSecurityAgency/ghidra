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
package sarif.export.func;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class ExtFunction implements IsfObject {

	String name;
	String namespace;
	boolean namespaceIsClass;
	String location;
	String comment;
	String repeatableComment;
	String value;
	
	String callingConvention;
	String callFixup;
	String signatureSource;
	String sourceType;
	
	boolean hasVarArgs;
	boolean isInline;
	boolean hasNoReturn;
	boolean hasCustomStorage;
	boolean isStackPurgeSizeValid;
	boolean isLibrary;
	boolean isGlobal;
	boolean isExternal;
	
	boolean isThunk;
	String thunkAddress;
	
	ExtFunctionStack stack;
	List<ExtFunctionRegVar> regVars = new ArrayList<>();
	
	ExtFunctionParam ret;
	List<ExtFunctionParam> params = new ArrayList<>();
	
	public ExtFunction(Function func, TaskMonitor monitor) {
		super();
		name = func.getName(true);
		location =  func.getEntryPoint().toString();
		comment = func.getComment();
		repeatableComment = func.getRepeatableComment();
		
		signatureSource = func.getSignatureSource().toString();
		SourceType srcType = func.getSymbol().getSource();
		sourceType = srcType.toString();
		if (srcType != SourceType.DEFAULT) {
			name = func.getName();
		}
		Namespace ns = func.getParentNamespace();
		if (!(ns instanceof GlobalNamespace)) {
			namespace = ns.getName(true);
			if (ns instanceof GhidraClass) {
				namespaceIsClass = true;
			}
		}
		if (func.getSignatureSource() != SourceType.DEFAULT) {
			value = func.getPrototypeString(true, true);
		}
		callingConvention = func.getCallingConventionName();
		callFixup = func.getCallFixup();
		
		hasVarArgs = func.hasVarArgs();
		isInline = func.isInline();
		hasNoReturn = func.hasNoReturn();
		hasCustomStorage = func.hasCustomVariableStorage();
		isStackPurgeSizeValid = func.isStackPurgeSizeValid();
		isLibrary = func.isLibrary();
		isGlobal = func.isGlobal();
		isExternal = func.isExternal();
		isThunk = func.isThunk();
		if (func.isThunk()) {
			Address thunkAddr = func.getThunkedFunction(false).getEntryPoint();
			thunkAddress = thunkAddr.toString();
		}
		
		stack = new ExtFunctionStack(func.getStackFrame(), hasCustomStorage);
		if (func.isStackPurgeSizeValid()) {
			stack.setPurgeSize(func.getStackPurgeSize());
		}
		
		Parameter rp = func.getReturn();
		ret = new ExtFunctionParam(rp);
		Parameter[] fnParams = func.getParameters();
		for (Parameter param : fnParams) {
			if (param.isRegisterVariable()) {
				regVars.add(new ExtFunctionRegVar(param));
			}
			params.add(new ExtFunctionParam(param));
		}
	}

}
