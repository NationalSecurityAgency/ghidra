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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;

import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.Section;
import ghidra.app.util.bin.format.macho.commands.SegmentNames;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * A class to represent the libobjc DYLIB Mach-O that resides within a DYLD cache
 */
public class LibObjcDylib {

	private MachHeader libObjcHeader;
	private Program program;
	private AddressSpace space;
	private MessageLog log;
	private TaskMonitor monitor;

	private LibObjcOptimization libObjcOptimization;

	/**
	 * Creates a new {@link LibObjcDylib}
	 * 
	 * @param libObjcHeader The libobjc DYLIB header
	 * @param program The {@link Program}
	 * @param space The {@link AddressSpace}
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 * @throws IOException if an IO-related error occurred while parsing
	 */
	public LibObjcDylib(MachHeader libObjcHeader, Program program, AddressSpace space,
			MessageLog log, TaskMonitor monitor) throws IOException {
		this.libObjcHeader = libObjcHeader;
		this.program = program;
		this.space = space;
		this.log = log;
		this.monitor = monitor;

		libObjcOptimization = parseLibObjcOptimization();
	}

	/**
	 * Marks up the libobjc DYLIB
	 */
	public void markup() {
		if (libObjcOptimization != null) {
			libObjcOptimization.markup(program, space, log, monitor);
		}
	}

	/**
	 * Parses the objc_opt_t structure which lives at the start of the __objc_opt_ro section in the
	 * libobjc DYLIB
	 * 
	 * @return The parsed {@link LibObjcOptimization objc_opt_t} structure, or null if it doesn't
	 *   exist
	 * @throws IOException if an IO-related error occurred while parsing
	 */
	private LibObjcOptimization parseLibObjcOptimization() throws IOException {
		Section section =
			libObjcHeader.getSection(SegmentNames.SEG_TEXT, LibObjcOptimization.SECTION_NAME);
		if (section == null) {
			return null;
		}
		return new LibObjcOptimization(program, space.getAddress(section.getAddress()));
	}
}
