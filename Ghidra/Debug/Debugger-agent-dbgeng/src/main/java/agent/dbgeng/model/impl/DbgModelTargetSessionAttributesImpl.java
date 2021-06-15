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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface2.DbgModelTargetSession;
import agent.dbgeng.model.iface2.DbgModelTargetSessionAttributes;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(
	name = "SessionAttributes",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Machine",
			type = DbgModelTargetSessionAttributesMachineImpl.class,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	})
public class DbgModelTargetSessionAttributesImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetSessionAttributes {

	protected final DbgModelTargetSessionAttributesMachineImpl machineAttributes;

	public DbgModelTargetSessionAttributesImpl(DbgModelTargetSession session) {
		super(session.getModel(), session, "Attributes", "SessionAttributes");

		this.machineAttributes = new DbgModelTargetSessionAttributesMachineImpl(this);

		changeAttributes(List.of(), List.of( //
			machineAttributes //
		), Map.of( //
			ARCH_ATTRIBUTE_NAME, "x86_64", //
			DEBUGGER_ATTRIBUTE_NAME, "dbgeng", //
			OS_ATTRIBUTE_NAME, "Windows", //
			ENDIAN_ATTRIBUTE_NAME, "little" //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return CompletableFuture.completedFuture(null);
	}

	/*
	@Override
	public String getArchitecture() {
		return machineAttributes.getTypedAttributeNowByName(ARCH_ATTRIBUTE_NAME, String.class, "");
	}
	
	@Override
	public String getDebugger() {
		return machineAttributes.getTypedAttributeNowByName(DEBUGGER_ATTRIBUTE_NAME, String.class,
			"");
	}
	
	@Override
	public String getOperatingSystem() {
		return machineAttributes.getTypedAttributeNowByName(OS_ATTRIBUTE_NAME, String.class, "");
	}
	*/

	@Override
	public void refreshInternal() {
		machineAttributes.refreshInternal();
	}

}
