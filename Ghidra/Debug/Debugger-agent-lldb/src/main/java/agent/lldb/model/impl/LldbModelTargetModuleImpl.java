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
import agent.lldb.model.iface2.LldbModelTargetModule;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;

@TargetObjectSchemaInfo(
	name = "Module",
	elements = {
		@TargetElementType(type = Void.class)
	},
	attributes = {
		@TargetAttributeType(
			name = "Sections",
			type = LldbModelTargetModuleSectionContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Symbols",
			type = LldbModelTargetSymbolContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "ImageName", type = String.class),
		@TargetAttributeType(name = "UUID", type = String.class),
		@TargetAttributeType(name = "Len", type = String.class),
		@TargetAttributeType(type = Void.class)
	})
public class LldbModelTargetModuleImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModule {

	protected static String indexModule(SBModule module) {
		return DebugClient.getId(module);
	}

	protected static String keyModule(SBModule module) {
		return PathUtils.makeKey(indexModule(module));
	}

	protected final SBTarget session;

	protected final LldbModelTargetSymbolContainerImpl symbols;
	protected final LldbModelTargetModuleSectionContainerImpl sections;

	public LldbModelTargetModuleImpl(LldbModelTargetModuleContainerImpl modules, SBModule module) {
		super(modules.getModel(), modules, keyModule(module), module, "Module");
		this.session = modules.session;

		this.symbols = new LldbModelTargetSymbolContainerImpl(this);
		this.sections = new LldbModelTargetModuleSectionContainerImpl(this);

		SBFileSpec fspec = module.GetFileSpec();
		changeAttributes(List.of(), List.of( //
			sections, //
			symbols //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, fspec.GetFilename(), //
			MODULE_NAME_ATTRIBUTE_NAME, fspec.GetDirectory() + "/" + fspec.GetFilename(), //
			"ImageName", fspec.GetDirectory() + "/" + fspec.GetFilename(), //
			"UUID", module.GetUUIDString() //
		/*
		"BaseAddress", space.getAddress(module.getKnownBase()), //
		"TimeStamp", module.getTimeStamp(), //
		"Len", Integer.toHexString(module.getSize()) //
		*/
		), "Initialized");

	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBModule module = (SBModule) getModelObject();
		module.GetDescription(stream);
		return stream.GetData();
	}

	protected Address doGetBase() {
		return null; //getModel().getAddressSpace("ram").getAddress(module.getKnownBase());
	}

	@Override
	public SBModule getModule() {
		return (SBModule) getModelObject();
	}

	public SBTarget getSession() {
		return session;
	}

	@Override
	public void setRange(AddressRangeImpl range) {
		changeAttributes(List.of(), List.of(), Map.of( //
			RANGE_ATTRIBUTE_NAME, range, //
			"BaseAddress", range.getMinAddress(), //
			"Len", Long.toHexString(range.getLength()) //
		), "Initialized");
	}

}
