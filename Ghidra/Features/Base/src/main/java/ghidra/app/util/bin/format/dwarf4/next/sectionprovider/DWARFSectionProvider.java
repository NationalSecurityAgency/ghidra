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

import ghidra.app.util.bin.ByteProvider;

import java.io.Closeable;
import java.io.IOException;

/**
 * A DWARFSectionProvider is responsible for allowing access to DWARF section data of
 * a Ghidra program.
 * <p>
 * Implementors of this interface should probably be registered in {@link DWARFSectionProviderFactory}
 * so they can be auto-detected when queried and also need to implement the static method:
 * <p>
 * <code>public static DWARFSectionProvider createSectionProviderFor(Program program)</code>
 * <p>
 */
public interface DWARFSectionProvider extends Closeable {
	public boolean hasSection(String... sectionNames);
	public ByteProvider getSectionAsByteProvider(String sectionName) throws IOException;
	public void close();
}
