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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * Operations for retrieving sections from a trace
 * 
 * <p>
 * Modules do not occupy target memory in and of themselves, but rather, their sections do. Thus,
 * only the section information is mapped out by memory address. Each section inherits its lifespan
 * from the containing module.
 */
public interface TraceModuleOperations {

	/**
	 * Get all modules
	 * 
	 * @return the (possibly empty) collection of modules
	 */
	Collection<? extends TraceModule> getAllModules();

	/**
	 * Get all modules loaded at the given snap
	 * 
	 * @param snap the snapshot key
	 * @return the collection of loaded modules
	 */
	Collection<? extends TraceModule> getLoadedModules(long snap);

	/**
	 * Get modules at the given snap and address
	 * 
	 * @param snap the snap
	 * @param address the address
	 * @return the (possibly empty) collection of modules
	 */
	Collection<? extends TraceModule> getModulesAt(long snap, Address address);

	/**
	 * Get the modules loaded at the given snap intersecting the given address range
	 * 
	 * @param lifespan the span which the module must intersect
	 * @param range the range of memory the module must intersect
	 * @return the collection of sections
	 */
	Collection<? extends TraceModule> getModulesIntersecting(Range<Long> lifespan,
			AddressRange range);

	/**
	 * Get all sections
	 * 
	 * @return the (possibly empty) collection of sections
	 */
	Collection<? extends TraceSection> getAllSections();

	/**
	 * Get sections at the given snap and address
	 * 
	 * @param snap the snap
	 * @param address the address
	 * @return the (possibly empty) collection of sections
	 */
	Collection<? extends TraceSection> getSectionsAt(long snap, Address address);

	/**
	 * Get the sections loaded at the given snap intersecting the given address range
	 * 
	 * @param lifespan the span which the section's (module's) lifespan must intersect
	 * @param range the range of memory each loaded section must intersect
	 * @return the collection of sections
	 */
	Collection<? extends TraceSection> getSectionsIntersecting(Range<Long> lifespan,
			AddressRange range);

}
