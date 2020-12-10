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
package ghidra.trace.model.modules;

import java.util.Collection;

import com.google.common.collect.Range;

import ghidra.program.model.address.AddressRange;
import ghidra.util.exception.DuplicateNameException;

/**
 * A store for loaded modules over time
 * 
 * <p>
 * The manager is not bound to any particular address space and may be used to access information
 * about any memory address. For module and section management, only section information can be
 * space bound.
 */
public interface TraceModuleManager extends TraceModuleOperations {
	/**
	 * Add a module
	 * 
	 * <p>
	 * Note that modules may overlap.
	 * 
	 * @param modulePath the "full name" of the module
	 * @param moduleName the "short name" of the module, usually its path on the file system
	 * @param range the address range of the module -- min should be the base address
	 * @param lifespan the span from load time to unload time
	 * @return the new module
	 */
	TraceModule addModule(String modulePath, String moduleName, AddressRange range,
			Range<Long> lifespan) throws DuplicateNameException;

	/**
	 * Add a module which is still loaded
	 * 
	 * @param modulePath the "full name" of the module
	 * @param range the address range of the module -- min should be the base address
	 * @param snap the snap at which the module was loaded
	 * @return the new module
	 */
	default TraceModule addLoadedModule(String modulePath, String moduleName, AddressRange range,
			long snap) throws DuplicateNameException {
		return addModule(modulePath, moduleName, range, Range.atLeast(snap));
	}

	/**
	 * Get modules by path
	 * 
	 * <p>
	 * Note it is possible the same module was loaded and unloaded multiple times. In that case,
	 * each load will have an separate record. It is also possible it was loaded at a different
	 * address, or that it's an entirely different module which happens to have the same path.
	 * 
	 * <p>
	 * Note that the "module path" in this case is not necessarily path of the module's image on the
	 * target file system, though this name often contains it. Rather, this is typically the full
	 * path to the module in the target debugger's object model. Likely, the "short name" is the
	 * file system path of the module's image.
	 * 
	 * @param modulePath the "full name" of the module
	 * @return the collection of modules having the given path
	 */
	Collection<? extends TraceModule> getModulesByPath(String modulePath);

	/**
	 * Get the module loaded at the given snap having the given path
	 * 
	 * @param snap the snap which the module's lifespan must contain
	 * @param modulePath the module's "full name"
	 * @return the module, or {@code null} if no module matches
	 */
	TraceModule getLoadedModuleByPath(long snap, String modulePath);

	/**
	 * Get sections by path
	 * 
	 * <p>
	 * Note because it's possible for a module path to be duplicated (but not within any overlapping
	 * snap), it is also possible for a section path to be duplicated.
	 * 
	 * @param sectionPath the "full name" of the section
	 * @return the collection of sections having the given path
	 */
	Collection<? extends TraceSection> getSectionsByPath(String sectionPath);

	/**
	 * Get the section loaded at the given snap having the given path
	 * 
	 * @param snap the snap which the section's (module's) lifespan must contain
	 * @param sectionPath the section's "full name"
	 * @return the section, or {@code null} if no section matches
	 */
	TraceSection getLoadedSectionByPath(long snap, String sectionPath);
}
