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

import java.util.List;

import java.io.IOException;
import java.net.MalformedURLException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.dwarf4.external.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A {@link DWARFSectionProvider} that reads .debug_info (and friends) sections from an external
 * ELF file that is referenced in the original ELF file's build-id or debuglink sections.
 * <p>
 * Creates a pinning reference from the temporary external ELF debug file to this SectionProvider
 * instance using the program's {@link Program#addConsumer(Object)}, and then releases the
 * consumer when this instance is closed, allowing the temporary Program to be destroyed.
 */
public class ExternalDebugFileSectionProvider extends BaseSectionProvider {
	public static final String PROGRAM_INFO_DWARF_EXTERNAL_DEBUG_FILE = "DWARF External Debug File";

	public static DWARFSectionProvider createExternalSectionProviderFor(Program program,
			TaskMonitor monitor) {
		try {
			ExternalDebugInfo extDebugInfo = ExternalDebugInfo.fromProgram(program);
			if (extDebugInfo == null) {
				return null;
			}
			Msg.info(ExternalDebugFilesService.class,
				"DWARF external debug information found: " + extDebugInfo);
			ExternalDebugFilesService edfs =
				DWARFExternalDebugFilesPlugin.getExternalDebugFilesService(
					SearchLocationRegistry.getInstance().newContext(program));
			FSRL extDebugFile = edfs.findDebugFile(extDebugInfo, monitor);
			if (extDebugFile == null) {
				return null;
			}
			Msg.info(ExternalDebugFilesService.class,
				"DWARF External Debug File: found: " + extDebugFile);
			FileSystemService fsService = FileSystemService.getInstance();
			try (
					RefdFile refdDebugFile = fsService.getRefdFile(extDebugFile, monitor);
					ByteProvider debugFileByteProvider =
						fsService.getByteProvider(refdDebugFile.file.getFSRL(), false, monitor);) {
				Object consumer = new Object();
				Language lang = program.getLanguage();
				CompilerSpec compSpec =
					lang.getCompilerSpecByID(program.getCompilerSpec().getCompilerSpecID());
				Program debugProgram =
					new ProgramDB("temp external debug info for " + program.getName(), lang,
						compSpec, consumer);
				ElfLoader elfLoader = new ElfLoader();
				elfLoader.load(debugFileByteProvider, null, List.of(), debugProgram, monitor,
					new MessageLog());
				ExternalDebugFileSectionProvider result =
					new ExternalDebugFileSectionProvider(debugProgram,
						debugFileByteProvider.getFSRL());
				debugProgram.release(consumer);
				return result;
			}
		}
		catch (IOException | CancelledException e) {
			// fall thru
		}
		return null;
	}

	private final FSRL externalDebugFileLocation;

	/**
	 * Creates a {@link ExternalDebugFileSectionProvider}
	 * 
	 * @param program the external ELF {@link Program} 
	 * @param externalDebugFileLocation the location where the external ELF debug file is located
	 */
	ExternalDebugFileSectionProvider(Program program, FSRL externalDebugFileLocation) {
		super(program);
		this.externalDebugFileLocation = externalDebugFileLocation;
		program.addConsumer(this);
	}

	@Override
	public void close() {
		if (program != null) {
			program.release(this);
		}
		super.close();

		program = null;
	}

	@Override
	public void updateProgramInfo(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		options.setString(PROGRAM_INFO_DWARF_EXTERNAL_DEBUG_FILE,
			externalDebugFileLocation.toString());
	}

	/**
	 * Returns the previously saved value of the external debug file location from the program's
	 * metadata.
	 *  
	 * @param program DWARF that previously was analyzed 
	 * @return FSRL of external debug file, or null if missing or corrupted value
	 */
	public static FSRL getExternalDebugFileLocation(Program program) {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		String fsrlStr = options.getString(PROGRAM_INFO_DWARF_EXTERNAL_DEBUG_FILE, null);
		try {
			return fsrlStr != null ? FSRL.fromString(fsrlStr) : null;
		}
		catch (MalformedURLException e) {
			return null;
		}
	}

}
