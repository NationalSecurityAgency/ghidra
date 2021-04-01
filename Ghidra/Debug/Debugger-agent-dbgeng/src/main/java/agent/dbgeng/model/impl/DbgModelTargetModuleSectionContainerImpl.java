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

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgModule;
import agent.dbgeng.manager.DbgModuleSection;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;

@TargetObjectSchemaInfo(name = "SectionContainer", elements = {
	@TargetElementType(type = DbgModelTargetModuleSectionImpl.class) }, attributes = {
		@TargetAttributeType(type = Void.class) }, canonicalContainer = true)
public class DbgModelTargetModuleSectionContainerImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetModuleSectionContainer {

	protected final DbgModule module;

	public DbgModelTargetModuleSectionContainerImpl(DbgModelTargetModule module) {
		super(module.getModel(), module, "Sections", "ModuleSections");
		this.module = module.getDbgModule();

	}

	@Override
	public CompletableFuture<Void> requestElements(boolean refresh) {
		return CompletableFuture.completedFuture(null);
		/*
		return module.listSections().thenAccept(byStart -> {
			List<TargetObject> sections;
			synchronized (this) {
				sections = byStart.values()
						.stream()
						.map(this::getModuleSection)
						.collect(Collectors.toList());
				setElements(sections, "Refreshed");
			}
		});
		*/
	}

	protected synchronized DbgModelTargetModuleSection getModuleSection(DbgModuleSection section) {
		DbgModelImpl impl = (DbgModelImpl) model;
		TargetObject modelObject = impl.getModelObject(section);
		if (modelObject != null) {
			return (DbgModelTargetModuleSection) modelObject;
		}
		return new DbgModelTargetModuleSectionImpl(this, section);
	}

}
