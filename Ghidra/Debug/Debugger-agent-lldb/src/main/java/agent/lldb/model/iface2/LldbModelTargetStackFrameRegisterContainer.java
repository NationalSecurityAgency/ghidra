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
package agent.lldb.model.iface2;

import SWIG.SBValue;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;

@TargetObjectSchemaInfo(
	name = "RegisterContainerInterface",
	attributeResync = ResyncMode.ALWAYS,
	attributes = {
		@TargetAttributeType(
			name = "General Purpose Registers",
			type = LldbModelTargetStackFrameRegisterBank.class,
			required = true),
		@TargetAttributeType(
			name = "Exception State Registers",
			type = LldbModelTargetStackFrameRegisterBank.class,
			required = true),
		@TargetAttributeType(
			name = "Floating Point Registers",
			type = LldbModelTargetStackFrameRegisterBank.class,
			required = true),
		@TargetAttributeType(type = Void.class)
	})
public interface LldbModelTargetStackFrameRegisterContainer
		extends LldbModelTargetRegisterContainer {

	public LldbModelTargetObject getTargetRegisterBank(SBValue val);

}
