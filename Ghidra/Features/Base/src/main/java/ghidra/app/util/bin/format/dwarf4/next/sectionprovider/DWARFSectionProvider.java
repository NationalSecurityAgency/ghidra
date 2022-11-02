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
import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A DWARFSectionProvider is responsible for allowing access to DWARF section data of
 * a Ghidra program.
 * <p>
 * Implementors of this interface need to be registered in 
 * {@link DWARFSectionProviderFactory#sectionProviderFactoryFuncs} and should implement the 
 * static method:
 * <p>
 * <code>public static DWARFSectionProvider createSectionProviderFor(Program program, TaskMonitor monitor)</code>
 * <p>
 * that is called via a java Function wrapper.
 * <p>
 * {@link DWARFSectionProvider} instances are responsible for {@link ByteProvider#close() closing} 
 * any {@link ByteProvider} that has been returned via 
 * {@link #getSectionAsByteProvider(String, TaskMonitor)} when the section provider instance is 
 * itself closed.
 * 
 */
public interface DWARFSectionProvider extends Closeable {

	/**
	 * Returns true if the specified section names are present.
	 * 
	 * @param sectionNames list of section names to test
	 * @return true if all are present, false if not present
	 */
	boolean hasSection(String... sectionNames);

	/**
	 * Returns a ByteProvider for the specified section.
	 * 
	 * @param sectionName name of the section
	 * @param monitor {@link TaskMonitor} to use when performing long operations
	 * @return ByteProvider, which will be closed by the section provider when itself is closed
	 * @throws IOException if error
	 */
	ByteProvider getSectionAsByteProvider(String sectionName, TaskMonitor monitor)
			throws IOException;

	@Override
	void close();

	/**
	 * Decorate the specified program with any information that is unique to this section provider.
	 * 
	 * @param program {@link Program} with an active transaction 
	 */
	default void updateProgramInfo(Program program) {
		// do nothing
	}

}
