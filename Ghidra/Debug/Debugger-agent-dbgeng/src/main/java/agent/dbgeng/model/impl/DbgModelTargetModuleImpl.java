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

import agent.dbgeng.manager.*;
import agent.dbgeng.model.iface2.DbgModelTargetModule;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(name = "Module", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Symbols", type = DbgModelTargetSymbolContainerImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = "BaseAddress", type = Address.class),
		@TargetAttributeType(name = "ImageName", type = String.class),
		@TargetAttributeType(name = "TimeStamp", type = Integer.class),
		@TargetAttributeType(name = "Len", type = String.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetModuleImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetModule {
	protected static String indexModule(DbgModule module) {
		return module.getName();
	}

	protected static String keyModule(DbgModule module) {
		return PathUtils.makeKey(indexModule(module));
	}

	protected final DbgProcess process;
	protected final DbgModule module;

	protected final DbgModelTargetSymbolContainerImpl symbols;
	//protected final DbgModelTargetModuleSectionContainerImpl sections;

	public DbgModelTargetModuleImpl(DbgModelTargetModuleContainerImpl modules, DbgModule module) {
		super(modules.getModel(), modules, keyModule(module), "Module");
		this.getModel().addModelObject(module, this);
		this.process = modules.process;
		this.module = module;

		this.symbols = new DbgModelTargetSymbolContainerImpl(this);
		//this.sections = new DbgModelTargetModuleSectionContainerImpl(this);

		AddressSpace space = getModel().getAddressSpace("ram");

		changeAttributes(List.of(), List.of( //
			symbols //
		//  sections.getName(), sections, //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getIndex(), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, module.getName(), //
			MODULE_NAME_ATTRIBUTE_NAME, module.getImageName(), //
			"BaseAddress", space.getAddress(module.getKnownBase()), //
			"ImageName", module.getImageName(), //
			"TimeStamp", module.getTimeStamp(), //
			"Len", Integer.toHexString(module.getSize()) //
		), "Initialized");

		DbgModuleSection section = new DbgModuleSection(module);
		Address min = space.getAddress(section.getStart());
		// Ghidra ranges are not inclusive at the end.
		Address max = space.getAddress(section.getStart() + section.getSize() - 1);
		AddressRange range = new AddressRangeImpl(min, max);

		changeAttributes(List.of(), List.of(), Map.of( //
			RANGE_ATTRIBUTE_NAME, range //
		), "Initialized");
	}

	protected Address doGetBase() {
		return getModel().getAddressSpace("ram").getAddress(module.getKnownBase());
	}

	@Override
	public DbgModule getDbgModule() {
		return module;
	}

	public DbgProcess getProcess() {
		return process;
	}

}
