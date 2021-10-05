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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.ByteOrder;
import SWIG.SBTarget;
import agent.lldb.model.iface2.LldbModelTargetSession;
import agent.lldb.model.iface2.LldbModelTargetSessionAttributes;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SessionAttributes",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Environment",
			type = LldbModelTargetSessionAttributesEnvironmentImpl.class,
			fixed = true),
		@TargetAttributeType(
			name = "Platform",
			type = LldbModelTargetSessionAttributesPlatformImpl.class,
			fixed = true),
		@TargetAttributeType(type = Void.class)
	})
public class LldbModelTargetSessionAttributesImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSessionAttributes {

	protected final LldbModelTargetSessionAttributesPlatformImpl platformAttributes;
	protected final LldbModelTargetSessionAttributesEnvironmentImpl environment;

	public LldbModelTargetSessionAttributesImpl(LldbModelTargetSession session) {
		super(session.getModel(), session, "Attributes", "SessionAttributes");

		this.platformAttributes = new LldbModelTargetSessionAttributesPlatformImpl(this);
		this.environment = new LldbModelTargetSessionAttributesEnvironmentImpl(this);

		SBTarget target = (SBTarget) session.getModelObject();
		String[] triple = target.GetTriple().split("-");
		ByteOrder order = target.GetByteOrder();
		String orderStr = "invalid";
		if (order.equals(ByteOrder.eByteOrderLittle)) {
			orderStr = "little";
		}
		if (order.equals(ByteOrder.eByteOrderBig)) {
			orderStr = "big";
		}
		if (order.equals(ByteOrder.eByteOrderPDP)) {
			orderStr = "pdp";
		}

		changeAttributes(List.of(), List.of( //
			platformAttributes, //
			environment //
		), Map.of( //
			ARCH_ATTRIBUTE_NAME, triple[0], //
			DEBUGGER_ATTRIBUTE_NAME, "lldb", //
			OS_ATTRIBUTE_NAME, triple[2], //
			ENDIAN_ATTRIBUTE_NAME, orderStr //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public void refreshInternal() {
		platformAttributes.refreshInternal();
	}

}
