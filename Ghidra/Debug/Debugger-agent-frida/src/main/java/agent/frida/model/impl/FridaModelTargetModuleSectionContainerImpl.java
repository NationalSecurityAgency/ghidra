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
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import agent.frida.manager.FridaModule;
import agent.frida.manager.FridaSection;
import agent.frida.model.iface2.FridaModelTargetModule;
import agent.frida.model.iface2.FridaModelTargetModuleSection;
import agent.frida.model.iface2.FridaModelTargetModuleSectionContainer;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;

@TargetObjectSchemaInfo(
	name = "SectionContainer",
	elements = {
		@TargetElementType(type = FridaModelTargetModuleSectionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class FridaModelTargetModuleSectionContainerImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetModuleSectionContainer {

	protected final FridaModelTargetModule module;

	public FridaModelTargetModuleSectionContainerImpl(FridaModelTargetModule module) {
		super(module.getModel(), module, "Sections", "ModuleSections");
		this.module = module;
		requestElements(RefreshBehavior.REFRESH_NEVER);
	}

	@Override
	public CompletableFuture<Void> requestElements(RefreshBehavior refresh) {
		return getManager().listModuleSections(module.getModule()).thenAccept(byStart -> {
			List<TargetObject> sections;
			synchronized (this) {
				sections = byStart.values()
						.stream()
						.map(this::getModuleSection)
						.collect(Collectors.toList());
				setElements(sections, "Refreshed");
				updateRange();
			}
		});
	}

	protected synchronized FridaModelTargetModuleSection getModuleSection(FridaSection section) {
		TargetObject targetObject = getMapObject(section);
		if (targetObject != null) {
			FridaModelTargetModuleSection targetSection =
				(FridaModelTargetModuleSection) targetObject;
			targetSection.setModelObject(section);
			return targetSection;
		}
		return new FridaModelTargetModuleSectionImpl(this, section);
	}

	public void updateRange() {
		Map<String, TargetObject> els = getCachedElements();
		Address min = null;
		Address max = null;
		for (TargetObject element : els.values()) {
			FridaModelTargetModuleSectionImpl section = (FridaModelTargetModuleSectionImpl) element;
			Address start = section.getStart();
			if (start.getOffset() > 0) {
				if (min == null || min.getOffset() > start.getOffset()) {
					min = start;
				}
			}
			Address stop = section.getEnd();
			if (stop.getOffset() > 0) {
				if (max == null || max.getOffset() < stop.getOffset()) {
					max = stop;
				}
			}
		}
		if (min != null & max != null) {
			module.setRange(new AddressRangeImpl(min, max));
		}
	}

	public FridaModule getModule() {
		return module.getModule();
	}

}
