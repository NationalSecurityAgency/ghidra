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
package ghidra.app.util.bin.format.dwarf.sectionprovider;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.AccessMode;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.dwarf.external.ExternalDebugFilesService;
import ghidra.app.util.bin.format.dwarf.external.ExternalDebugInfo;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.framework.options.Options;
import ghidra.plugin.importer.ImporterUtilities;
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
			Msg.info(ExternalDebugFileSectionProvider.class,
				"DWARF external debug information found: " + extDebugInfo);
			ExternalDebugFilesService edfs = ExternalDebugFilesService.forProgram(program);
			File extDebugFile = edfs.find(extDebugInfo, monitor);
			if (extDebugFile == null) {
				return null;
			}
			Msg.info(ExternalDebugFileSectionProvider.class,
				"DWARF External Debug File: found: " + extDebugFile);
			FSRL fsrl = FileSystemService.getInstance().getLocalFSRL(extDebugFile);
			try (ByteProvider debugFileByteProvider =
				new FileByteProvider(extDebugFile, fsrl, AccessMode.READ)) {
				Object consumer = new Object();
				Language lang = program.getLanguage();
				LoadSpec origLoadSpec = ImporterUtilities.getLoadSpec(program);
				if (origLoadSpec == null) {
					return null;
				}

				CompilerSpec compSpec = origLoadSpec.getLanguageCompilerSpec().getCompilerSpec();

				Program debugProgram =
					new ProgramDB("temp external debug info for " + program.getName(), lang,
						compSpec, consumer);

				Loader origLoader = origLoadSpec.getLoader();
				List<Option> defaultOptions = origLoader.getDefaultOptions(debugFileByteProvider,
					origLoadSpec, debugProgram, false, false);

				ElfLoader elfLoader = new ElfLoader();
				ImporterSettings settings =
					new ImporterSettings(debugFileByteProvider, debugProgram.getName(), null, null,
						false, origLoadSpec, defaultOptions, consumer, new MessageLog(), monitor);
				elfLoader.load(debugProgram, settings);

				ExternalDebugFileSectionProvider result = new ExternalDebugFileSectionProvider(
					debugProgram, debugFileByteProvider.getFSRL());
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
		// we close the parent class'es program instance here because we repurposed it from its
		// normal use-case of referring to the main program 
		if (program != null) {
			program.release(this);
		}
		super.close();

		program = null;
	}

	public Program getExternalProgram() {
		return program;
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
