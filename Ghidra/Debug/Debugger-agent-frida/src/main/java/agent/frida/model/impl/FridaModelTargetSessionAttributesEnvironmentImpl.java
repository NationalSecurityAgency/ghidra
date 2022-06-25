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

import agent.frida.manager.FridaSession;
import agent.frida.model.iface2.FridaModelTargetSessionAttributes;
import agent.frida.model.iface2.FridaModelTargetSessionAttributesEnvironment;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SessionAttributesEnvironment",
	attributes = {
		@TargetAttributeType(type = Object.class)
	})
public class FridaModelTargetSessionAttributesEnvironmentImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSessionAttributesEnvironment {

	FridaSession session;

	public FridaModelTargetSessionAttributesEnvironmentImpl(
			FridaModelTargetSessionAttributes attributes) {
		super(attributes.getModel(), attributes, "Environment", "SessionAttributesEnvironment");

		session = (FridaSession) getModelObject();

		changeAttributes(List.of(), List.of(), Map.of( //
			"Debugger", "Frida", //
			"Debugger Attached", session.getAttribute("debugger"), //
			"Debugger Version", session.getAttribute("version"), //
			"Code Signing", session.getAttribute("codeSigning"), //
			"Page Size", session.getAttribute("pageSize"), //
			"Pointer Size", session.getAttribute("pointerSize"), //
			"Heap Size", session.getAttribute("heapSize"), //
			"Runtime", session.getAttribute("runtime"), //
			"Kernel", session.getAttribute("kernel") //
		), "Initialized");
		
		getManager().addEventsListener(this);
	}

}
