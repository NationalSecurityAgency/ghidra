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

import agent.frida.manager.*;
import agent.frida.model.iface2.FridaModelTargetSessionAttributes;
import agent.frida.model.iface2.FridaModelTargetSessionAttributesPlatform;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "SessionAttributesPlatform",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(type = Object.class)
	})
public class FridaModelTargetSessionAttributesPlatformImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSessionAttributesPlatform {

	static String ARCH_ATTRIBUTE_NAME = "Arch";
	static String OS_ATTRIBUTE_NAME = "OS";
	static String DEBUGGER_ATTRIBUTE_NAME = "Debugger";

	FridaSession session;

	public FridaModelTargetSessionAttributesPlatformImpl(
			FridaModelTargetSessionAttributes attributes) {
		super(attributes.getModel(), attributes, "Platform", "SessionAttributesPlatform");

		session = (FridaSession) getModelObject();

		changeAttributes(List.of(), List.of(), Map.of( //
			ARCH_ATTRIBUTE_NAME, session.getAttribute("arch"), //
			OS_ATTRIBUTE_NAME, session.getAttribute("os"), //
			DEBUGGER_ATTRIBUTE_NAME, "Frida" //
		), "Initialized");

		getManager().addEventsListener(this);
	}

}
