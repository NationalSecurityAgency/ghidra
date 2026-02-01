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
package sarif.export.data;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ISF.IsfFunction;
import ghidra.program.model.data.ISF.IsfUtilities;

public class ExtIsfFunction extends IsfFunction {

	String comment;
	String callingConventionName;
	boolean hasVarArgs;
	boolean hasNoReturn;
	JsonObject retType;
	JsonArray params;
	
	public ExtIsfFunction(FunctionDefinition funcDef) {
		super(funcDef);
		comment = funcDef.getDescription();
		callingConventionName = funcDef.getCallingConventionName();
		hasVarArgs = funcDef.hasVarArgs();
		hasNoReturn = funcDef.hasNoReturn();
		
		retType = new JsonObject();
		DataType rt = funcDef.getReturnType();
		if (rt != null && rt != DataType.DEFAULT) {
			retType.addProperty("name", rt.getName());
			retType.addProperty("location", rt.getCategoryPath().getPath());
			retType.addProperty("kind", IsfUtilities.getKind(rt));
			retType.addProperty("size", rt.getLength());
		}
		
		params = new JsonArray();
		ParameterDefinition[] vars = funcDef.getArguments();
		for (ParameterDefinition var : vars) {
			JsonObject param = new JsonObject();
			params.add(param);
			DataType dt = var.getDataType();
			param.addProperty("name", var.getName());
			param.addProperty("size", var.getLength());
			param.addProperty("ordinal", var.getOrdinal());
			param.addProperty("comment", var.getComment());
			if (dt != null) {
				param.addProperty("name", dt.getName());
				param.addProperty("location", dt.getCategoryPath().getPath());
				param.addProperty("kind", IsfUtilities.getKind(dt));
			} 
		}

	}

}
