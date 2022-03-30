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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;

import agent.frida.frida.FridaClient;
import agent.frida.manager.FridaFunction;
import agent.frida.model.iface2.FridaModelTargetFunction;
import agent.frida.model.iface2.FridaModelTargetStackFrame;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Function",
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class FridaModelTargetFunctionImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetFunction {

	protected static String keyFunction(FridaFunction fn) {
		return PathUtils.makeKey(FridaClient.getId(fn));
	}

	protected final FridaModelTargetStackFrame frame;

	public FridaModelTargetFunctionImpl(FridaModelTargetStackFrame frame, FridaFunction function) {
		super(frame.getModel(), frame, "Function", function, "Function");
		this.frame = frame;

		if (function != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
				"Module Name", function.getModuleName(), //
				"Function Name", function.getFunctionName(), //
				"File Name", function.getFileName(), //
				"Line Number", function.getLineNumber() //
			), "Initialized");
		}
	}

	public String getDescription(int level) {
		FridaFunction function = (FridaFunction) getModelObject();
		return function.getFunctionName();
	}

}
