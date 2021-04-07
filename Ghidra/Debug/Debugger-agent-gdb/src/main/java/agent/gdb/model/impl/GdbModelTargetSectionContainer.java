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
import java.util.stream.Collectors;

import agent.gdb.manager.GdbModuleSection;
import ghidra.dbg.agent.DefaultTargetObject;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetSectionContainer;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "SectionContainer",
	attributes = {
		@TargetAttributeType(type = Void.class) },
	canonicalContainer = true)
public class GdbModelTargetSectionContainer
		extends DefaultTargetObject<GdbModelTargetSection, GdbModelTargetModule>
		implements TargetSectionContainer {
	public static final String NAME = "Sections";

	protected final GdbModelImpl impl;
	protected final GdbModelTargetModule module;

	public GdbModelTargetSectionContainer(GdbModelTargetModule module) {
		super(module.impl, module, NAME, "SectionContainer");
		this.impl = module.impl;
		this.module = module;
	}

	protected void updateUsingSections(Map<String, GdbModuleSection> byName) {
		List<GdbModelTargetSection> sections;
		synchronized (this) {
			sections = byName.values()
					.stream()
					.filter(s -> s.getAttributes().contains("ALLOC"))
					.map(this::getTargetSection)
					.collect(Collectors.toList());
		}
		setElements(sections, "Refreshed");
		parent.sectionsRefreshed(); // recompute base
	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		// getKnownSections is not guaranteed to be populated
		// listSections is cached by manager, so just use it always
		return module.module.listSections().thenAccept(this::updateUsingSections);
	}

	protected synchronized GdbModelTargetSection getTargetSection(GdbModuleSection section) {
		TargetObject modelObject = impl.getModelObject(section);
		if (modelObject != null) {
			return (GdbModelTargetSection) modelObject;
		}
		return new GdbModelTargetSection(this, module, section);
	}
}
