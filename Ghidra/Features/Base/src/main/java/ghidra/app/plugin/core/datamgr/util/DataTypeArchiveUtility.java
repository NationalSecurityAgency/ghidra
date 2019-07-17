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
package ghidra.app.plugin.core.datamgr.util;

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.util.opinion.*;
import ghidra.framework.Application;
import ghidra.framework.options.Options;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class DataTypeArchiveUtility {

	private static HashMap<String, String> archiveRemappings = new HashMap<String, String>();
	static {
		archiveRemappings.put("windows_vs12.gdt", "windows_vs12_32.gdt");  // generic VisualStudio archive reference
		archiveRemappings.put("windows_vs.gdt", "windows_vs12_32.gdt");  // generic VisualStudio archive reference
		archiveRemappings.put("windows_VS9.gdt", "windows_vs12_32.gdt"); // archives have matching UniversalIDs

		archiveRemappings.put("generic_C_lib.gdt", "generic_clib.gdt");  // generic C-library archive reference
	}

	public static final Map<String, ResourceFile> GHIDRA_ARCHIVES =
		new HashMap<String, ResourceFile>();
	static {
		for (ResourceFile file : Application.findFilesByExtensionInApplication(
			FileDataTypeManager.SUFFIX)) {
			String name = file.getName();
			ResourceFile resourceFile = GHIDRA_ARCHIVES.get(name);
			if (resourceFile == null) {
				GHIDRA_ARCHIVES.put(file.getName(), file);
			}
			else {
				Msg.showError(DataTypeManagerHandler.class, null, "Duplicate Archive Name Error",
					"Duplicate datatype archive name detected and is not supported:\n  " +
						resourceFile.getAbsolutePath() + "\n  " + file.getAbsolutePath());
			}
		}
	}

	private static final String RELATIVE_PATH_PREFIX = ".";

	// static util class
	private DataTypeArchiveUtility() {
	}

	public static String getRemappedArchiveName(String archiveName) {

		// TODO: change remapping of old archive names to use
		// file-specified remappings (e.g., xml file)

		return archiveRemappings.get(archiveName);
	}

	/**
	 * Find an archive file within the Ghidra installation.
	 * If archive has been replaced between Ghidra releases,
	 * it may be re-mapped to a newer resource file.
	 * @param archiveName archive file name
	 * @return existing resource file or null if not found
	 */
	public static ResourceFile findArchiveFile(String archiveName) {
		if (!archiveName.endsWith(FileDataTypeManager.SUFFIX)) {
			archiveName = archiveName + FileDataTypeManager.SUFFIX;
		}
		archiveName = archiveName.replace('\\', '/');
		if (archiveName.indexOf(':') >= 0 || archiveName.charAt(0) == '/') {
			return null;
		}
		if (archiveName.startsWith(RELATIVE_PATH_PREFIX)) {
			archiveName = archiveName.substring(RELATIVE_PATH_PREFIX.length());
		}
		else {
			archiveName = "/" + archiveName; // ensure we match on whole path element name
		}
		// relative path starts with "/"
		for (ResourceFile file : GHIDRA_ARCHIVES.values()) {
			String path = file.getAbsolutePath().replace('\\', '/');
			// NOTE: existence check added to facilitate testing
			if (path.endsWith(archiveName) && file.exists()) {
				return file;
			}
		}
		// Note: recursion could blow-out if circular archive re-mapping defined (maps should be defined properly)
		String remappedRelativePath = getRemappedArchiveName(archiveName.substring(1));
		if (remappedRelativePath != null) {
			return findArchiveFile(remappedRelativePath);
		}
		return null;
	}

	/**
	 * get a list of known applicable .GDT archives for the given program.
	 * 
	 * @param program - program to lookup archives for
	 * @return list of archives that could apply to this program
	 */
	public static List<String> getArchiveList(Program program) {
		List<String> list = new ArrayList<String>();

		Options props = program.getOptions(Program.PROGRAM_INFO);
		String format = props.getString("Executable Format", "");

		int size = program.getAddressFactory().getDefaultAddressSpace().getSize();

		if (format.equals(PeLoader.PE_NAME) ||
			(format.equals(CoffLoader.COFF_NAME) && isVisualStudio(program))) {
			// TODO: add in win7/win10
			if (size == 64) {
				list.add("windows_vs12_64");
			}
			else {
				list.add("windows_vs12_32");
			}
		}
		else if (format.equals(MachoLoader.MACH_O_NAME)) {
			// list.add("Cocoa");  // no more cocoa puffs for you
			// TODO: should we have a 64/32 version?
			// TODO: multiple OSX versions
			list.add("mac_osx");
		}
		else if (size == 64) {
			list.add("generic_clib_64");
		}
		// everyone else gets generic clib that was parsed as 32 bit wordsize
		else {
			list.add("generic_clib");
		}
		return list;
	}

	/**
	 * Try to determine if this COFF file was produced by the Microsoft Visual Studio tools
	 * Currently we look for specific sections that are indicative of Visual Studio
	 *   The .drectve contains options that are passed to the linker
	 *   The .debug$S is a non-standard debug section (which usually has the string "Microsoft" in it)
	 * These particular sections seem to be universally present over many versions of Visual Studio
	 * GNU bfd recognizes these sections as Microsoft Visual Studio specific
	 * 
	 * @param program to check for the magic named sections
	 * 
	 * @return true is (either section is present and) we think this is Visual Studio
	 */
	private static boolean isVisualStudio(Program program) {
		return (program.getMemory().getBlock(".drectve") != null) ||
			(program.getMemory().getBlock(".debug$S") != null);
	}
}
