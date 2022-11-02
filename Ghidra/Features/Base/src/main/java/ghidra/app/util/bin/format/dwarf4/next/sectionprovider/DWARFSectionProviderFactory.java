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
package ghidra.app.util.bin.format.dwarf4.next.sectionprovider;

import java.io.Closeable;
import java.util.List;
import java.util.function.BiFunction;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Auto-detects which {@link DWARFSectionProvider} matches a Ghidra program.
 */
public class DWARFSectionProviderFactory {

	/**
	 * A list of functions that will create a {@link DWARFSectionProvider}.
	 * <p>
	 * The method should return null if it can't parse the data it found in the {@link Program}.
	 * <p>
	 * The method does NOT need to worry about validating the presence of DWARF debug info
	 * sections, as that will be done later via calls to DWARFSectionProvider.hasSection() and
	 * DWARFSectionProvider.getSectionAsByteProvider().
	 * <p>
	 * The method should not throw anything, instead just return a NULL.
	 */
	private static final List<BiFunction<Program, TaskMonitor, DWARFSectionProvider>> sectionProviderFactoryFuncs =
		List.of(
			BaseSectionProvider::createSectionProviderFor,
			DSymSectionProvider::createSectionProviderFor,
			ExternalDebugFileSectionProvider::createExternalSectionProviderFor);

	/**
	 * Iterates through the statically registered {@link #sectionProviderFactoryFuncs factory funcs},
	 * trying each factory method until one returns a {@link DWARFSectionProvider} 
	 * that can successfully retrieve the {@link DWARFSectionNames#MINIMAL_DWARF_SECTIONS minimal} 
	 * sections we need to do a DWARF import.
	 * <p>
	 * The resulting {@link DWARFSectionProvider} is {@link Closeable} and it is the caller's
	 * responsibility to ensure that the object is closed when done. 
	 * 
	 * @param program
	 * @param monitor {@link TaskMonitor}
	 * @return {@link DWARFSectionProvider} that should be closed by the caller or NULL if no
	 * section provider types match the specified program.
	 */
	public static DWARFSectionProvider createSectionProviderFor(Program program,
			TaskMonitor monitor) {
		for (BiFunction<Program, TaskMonitor, DWARFSectionProvider> factoryFunc : sectionProviderFactoryFuncs) {
			DWARFSectionProvider sp = factoryFunc.apply(program, monitor);
			if (sp != null) {
				try {
					if (sp.hasSection(DWARFSectionNames.MINIMAL_DWARF_SECTIONS)) {
						return sp;
					}

					// if normal sections were not found, look for compressed sections in the
					// same provider
					sp = new CompressedSectionProvider(sp);
					if (sp.hasSection(DWARFSectionNames.MINIMAL_DWARF_SECTIONS)) {
						return sp;
					}
				}
				catch (Exception e) {
					Msg.warn(DWARFSectionProviderFactory.class,
						"Problem detecting DWARFSectionProvider", e);
				}
				sp.close();
			}
		}
		return null;
	}

}
