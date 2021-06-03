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
package agent.gdb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbInferior;
import agent.gdb.manager.GdbModule;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;

@TargetObjectSchemaInfo(
	name = "Module",
	elements = { //
		@TargetElementType(type = Void.class) //
	},
	attributes = { // 
		@TargetAttributeType(type = Void.class) //
	})
public class GdbModelTargetModule extends
		DefaultTargetObject<TargetObject, GdbModelTargetModuleContainer> implements TargetModule {

	public static final String VISIBLE_RANGE_ATTRIBUTE_NAME = "range";
	public static final String VISIBLE_MODULE_NAME_ATTRIBUTE_NAME = "module name";

	protected static String indexModule(GdbModule module) {
		return module.getName();
	}

	protected static String keyModule(GdbModule module) {
		return PathUtils.makeKey(indexModule(module));
	}

	protected final GdbModelImpl impl;
	protected final GdbInferior inferior;
	protected final GdbModule module;

	protected final GdbModelTargetSectionContainer sections;
	protected final GdbModelTargetSymbolContainer symbols;
	// TODO Types? See GDB's ptype, but that'll require some C parsing

	protected AddressRange range;

	public GdbModelTargetModule(GdbModelTargetModuleContainer modules, GdbModule module) {
		super(modules.impl, modules, keyModule(module), "Module");
		this.impl = modules.impl;
		this.inferior = modules.inferior;
		this.module = module;
		impl.addModelObject(module, this);
		impl.addModelObject(module.getName(), this);

		this.sections = new GdbModelTargetSectionContainer(this);
		this.symbols = new GdbModelTargetSymbolContainer(this);

		range = doGetRange(); // Likely [0,0]
		changeAttributes(List.of(), List.of(sections, symbols), Map.of( //
			VISIBLE_RANGE_ATTRIBUTE_NAME, range, //
			VISIBLE_MODULE_NAME_ATTRIBUTE_NAME, module.getName(), //
			RANGE_ATTRIBUTE_NAME, range, //
			MODULE_NAME_ATTRIBUTE_NAME, module.getName(), //
			SHORT_DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			DISPLAY_ATTRIBUTE_NAME, getDisplay() //
		), "Initialized");
	}

	public CompletableFuture<Void> init() {
		return sections.requestElements(true).exceptionally(ex -> {
			impl.reportError(this, "Could not initialize module sections and base", ex);
			return null;
		});
	}

	@TargetAttributeType(name = GdbModelTargetSectionContainer.NAME, required = true, fixed = true)
	public GdbModelTargetSectionContainer getSections() {
		return sections;
	}

	@TargetAttributeType(name = GdbModelTargetSymbolContainer.NAME, required = true, fixed = true)
	public GdbModelTargetSymbolContainer getSymbols() {
		return symbols;
	}

	@Override
	public String getDisplay() {
		String shortName = module.getName();
		int sep = shortName.lastIndexOf('/');
		if (sep > 0 && sep < shortName.length()) {
			shortName = shortName.substring(sep + 1);
		}
		return shortName;
	}

	protected AddressRange doGetRange() {
		Long base = module.getKnownBase();
		Long max = module.getKnownMax();
		max = max == null ? base : (Long) (max - 1); // GDB gives end+1
		if (base == null) {
			Address addr = impl.space.getMinAddress();
			return new AddressRangeImpl(addr, addr);
		}
		return new AddressRangeImpl(impl.space.getAddress(base), impl.space.getAddress(max));
	}

	public void sectionsRefreshed() {
		range = doGetRange();
		changeAttributes(List.of(),
			Map.of(RANGE_ATTRIBUTE_NAME, range, VISIBLE_RANGE_ATTRIBUTE_NAME, range),
			"Sections Refreshed");
	}

	@Override
	public AddressRange getRange() {
		return range;
	}

	// TODO: Consider a way to override the "hidden" field of an attribute
	// Otherwise, this information is duplicated in memory and on the wire
	@TargetAttributeType(name = VISIBLE_RANGE_ATTRIBUTE_NAME)
	public AddressRange getVisibleRange() {
		return range;
	}

	@TargetAttributeType(name = VISIBLE_MODULE_NAME_ATTRIBUTE_NAME)
	public String getVisibleModuleName() {
		return module.getName();
	}

}
