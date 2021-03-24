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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Auto-detects which {@link DWARFSectionProvider} matches a Ghidra program.
 */
public class DWARFSectionProviderFactory {

	/**
	 * A list of references to static methods that will create a {@link DWARFSectionProvider}.
	 * <p>
	 * The method should return null if it can't parse the data it found in the {@link Program}.
	 * <p>
	 * The method does NOT need to worry about validating the presence of DWARF debug info
	 * sections, as that will be done in {@link #createSectionProviderFor(Program)}.
	 * <p>
	 * The method should not throw anything, instead just return a NULL.
	 */
	private static final List<Function<Program, DWARFSectionProvider>> sectionProviderFactoryFuncs =
		new ArrayList<>();

	static {
		sectionProviderFactoryFuncs.add(BaseSectionProvider::createSectionProviderFor);
		sectionProviderFactoryFuncs.add(DSymSectionProvider::createSectionProviderFor);
	}

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
	 * @return {@link DWARFSectionProvider} that should be closed by the caller or NULL if no
	 * section provider types match the specified program.
	 */
	public static DWARFSectionProvider createSectionProviderFor(Program program) {
		for (Function<Program, DWARFSectionProvider> factoryFunc : sectionProviderFactoryFuncs) {
			DWARFSectionProvider sp = factoryFunc.apply(program);
			if (sp != null) {
				try {
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
