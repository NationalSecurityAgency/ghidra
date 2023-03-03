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
import agent.frida.model.iface2.FridaModelTargetSession;
import agent.frida.model.iface2.FridaModelTargetSessionAttributes;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "SessionAttributes",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Environment",
			type = FridaModelTargetSessionAttributesEnvironmentImpl.class,
			fixed = true),
		@TargetAttributeType(
			name = "Platform",
			type = FridaModelTargetSessionAttributesPlatformImpl.class,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	})
public class FridaModelTargetSessionAttributesImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSessionAttributes {

	protected final FridaModelTargetSessionAttributesPlatformImpl platformAttributes;
	protected final FridaModelTargetSessionAttributesEnvironmentImpl environment;

	public FridaModelTargetSessionAttributesImpl(FridaModelTargetSession session) {
		super(session.getModel(), session, "Attributes", "SessionAttributes");

		this.platformAttributes = new FridaModelTargetSessionAttributesPlatformImpl(this);
		this.environment = new FridaModelTargetSessionAttributesEnvironmentImpl(this);

		requestAttributes(RefreshBehavior.REFRESH_NEVER);

		FridaSession s = (FridaSession) session.getModelObject();
		changeAttributes(List.of(), List.of( //
			platformAttributes, //
			environment //
		), Map.of( //
			ARCH_ATTRIBUTE_NAME, s.getAttribute("arch"), //
			DEBUGGER_ATTRIBUTE_NAME, "Frida", //
			OS_ATTRIBUTE_NAME, s.getAttribute("os") //
			//ENDIAN_ATTRIBUTE_NAME, orderStr //
		), "Initialized");

		getManager().addEventsListener(this);
	}

}
