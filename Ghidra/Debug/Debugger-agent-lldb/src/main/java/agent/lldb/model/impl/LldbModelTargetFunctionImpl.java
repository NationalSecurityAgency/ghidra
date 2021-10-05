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

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.model.iface2.LldbModelTargetFunction;
import agent.lldb.model.iface2.LldbModelTargetStackFrame;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.datastruct.WeakValueHashMap;

@TargetObjectSchemaInfo(
	name = "Function",
	attributes = {
		@TargetAttributeType(type = Object.class)
	},
	canonicalContainer = true)
public class LldbModelTargetFunctionImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetFunction {

	protected static String keyFunction(SBFunction fn) {
		return PathUtils.makeKey(DebugClient.getId(fn));
	}

	protected final LldbModelTargetStackFrame frame;

	protected final Map<Integer, LldbModelTargetStackFrameImpl> framesByLevel =
		new WeakValueHashMap<>();

	public LldbModelTargetFunctionImpl(LldbModelTargetStackFrame frame, SBFunction function) {
		super(frame.getModel(), frame, "Function", function, "Function");
		this.frame = frame;

		if (function.IsValid()) {
			AddressSpace space = getModel().getAddressSpace("ram");
			Address min = space.getAddress(function.GetStartAddress().GetOffset().longValue());
			Address max = space.getAddress(function.GetStartAddress().GetOffset().longValue());

			String name = function.GetName();
			String displayName = function.GetDisplayName();
			if (displayName == null) {
				displayName = name;
			}
			String mangledName = function.GetMangledName();
			if (mangledName == null) {
				mangledName = name;
			}
			long prologSize = function.GetPrologueByteSize();
			changeAttributes(List.of(), List.of(), Map.of( //
				DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
				"Start", min, //
				"End", max, //
				"Language", function.GetLanguage().toString(), //
				"Name", name, //
				"Display Name", displayName, //
				"Mangled Name", mangledName, //
				"Prolog Size", prologSize, //
				"Block", getBlockDescription(function.GetBlock()) //
			), "Initialized");
		}
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBFunction function = (SBFunction) getModelObject();
		function.GetDescription(stream);
		return stream.GetData();
	}

	public String getBlockDescription(SBBlock block) {
		SBStream stream = new SBStream();
		block.GetDescription(stream);
		return stream.GetData();
	}

}
