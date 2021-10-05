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
import java.util.stream.Collectors;

import SWIG.SBModule;
import SWIG.SBSection;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRangeImpl;

@TargetObjectSchemaInfo(
	name = "SectionContainer",
	elements = {
		@TargetElementType(type = LldbModelTargetModuleSectionImpl.class) },
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class LldbModelTargetModuleSectionContainerImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetModuleSectionContainer {

	protected final LldbModelTargetModule module;

	public LldbModelTargetModuleSectionContainerImpl(LldbModelTargetModule module) {
		super(module.getModel(), module, "Sections", "ModuleSections");
		this.module = module;
		requestElements(false);
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
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

	protected synchronized LldbModelTargetModuleSection getModuleSection(SBSection section) {
		TargetObject targetObject = getMapObject(section);
		if (targetObject != null) {
			LldbModelTargetModuleSection targetSection =
				(LldbModelTargetModuleSection) targetObject;
			targetSection.setModelObject(section);
			return targetSection;
		}
		return new LldbModelTargetModuleSectionImpl(this, section);
	}

	public void updateRange() {
		Map<String, TargetObject> elements = getCachedElements();
		Address min = null;
		Address max = null;
		for (TargetObject element : elements.values()) {
			LldbModelTargetModuleSectionImpl section = (LldbModelTargetModuleSectionImpl) element;
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
		module.setRange(new AddressRangeImpl(min, max));
	}

	public SBModule getModule() {
		return module.getModule();
	}

}
