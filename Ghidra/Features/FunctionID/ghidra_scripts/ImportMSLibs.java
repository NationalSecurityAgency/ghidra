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
//Massive recursive import for a MS Visual Studio installation directory
//@category FunctionID
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.Loader;
import ghidra.app.util.opinion.MSCoffLoader;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.CancelOnlyWrappingTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class ImportMSLibs extends GhidraScript {
	final static Predicate<Loader> LOADER_FILTER = new SingleLoaderFilter(MSCoffLoader.class);
	final static LoadSpecChooser LOADSPEC_CHOOSER = new CsHintLoadSpecChooser("windows");

	@Override
	protected void run() throws Exception {
		DomainFolder root = askProjectFolder("Choose a top-level domain folder");

		ArrayList<File> directories = new ArrayList<File>();

		// ALL .LIB files under this directory will be inspected/imported as Win COFF
		while (true) {
			try {
				File directory =
					askDirectory("Add a top-level import directory (cancel to quit)", "Add");
				directories.add(directory);
			}
			catch (CancelledException e) {
				break;
			}
		}

		ArrayList<File> non_debug_files = new ArrayList<File>();
		ArrayList<File> debug_files = new ArrayList<File>();

		findFiles(non_debug_files, debug_files, directories);
		MessageLog log = new MessageLog();

		monitor.initialize(non_debug_files.size() + debug_files.size());

		for (File file : non_debug_files) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			importLibrary(root, file, false, log);
		}

		for (File file : debug_files) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);
			importLibrary(root, file, true, log);
		}
	}

	private void importLibrary(DomainFolder root, File file, boolean isDebug, MessageLog log)
			throws CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, IOException {
		try (RandomAccessByteProvider provider = new RandomAccessByteProvider(file) ) {
			if ( !CoffArchiveHeader.isMatch(provider)) { return; }
			
			CoffArchiveHeader coffArchiveHeader = CoffArchiveHeader.read(provider, TaskMonitor.DUMMY);
			HashSet<Long> offsetsSeen = new HashSet<Long>();
			for (CoffArchiveMemberHeader archiveMemberHeader : coffArchiveHeader.getArchiveMemberHeaders()) {
				monitor.checkCanceled();
				if (offsetsSeen.contains(archiveMemberHeader.getPayloadOffset())) {
					continue;
				}
				offsetsSeen.add(archiveMemberHeader.getPayloadOffset());
				if (archiveMemberHeader.isCOFF()) {
					try (ByteProvider coffProvider = new ByteProviderWrapper(provider,
						archiveMemberHeader.getPayloadOffset(), archiveMemberHeader.getSize())) {
						CoffFileHeader header = new CoffFileHeader(coffProvider);
						if (CoffMachineType.isMachineTypeDefined(header.getMagic())) {
							String preferredName = archiveMemberHeader.getName();
							String[] splits = splitPreferredName(preferredName);

							List<Program> programs =
								AutoImporter.importFresh(
									coffProvider,
									root,
									this,
									log,
									new CancelOnlyWrappingTaskMonitor(monitor),
									LOADER_FILTER,
									LOADSPEC_CHOOSER,
									mangleNameBecauseDomainFoldersAreSoRetro(splits[splits.length - 1]),
									OptionChooser.DEFAULT_OPTIONS,
									MultipleProgramsStrategy.ONE_PROGRAM_OR_EXCEPTION);

							if (programs == null || programs.isEmpty()) {
								printerr("no programs loaded from " + file + " - " +
									preferredName);
							}

							if (programs != null) {
								for (Program program : programs) {
									program.release(this);
									DomainFolder destination =
										establishFolder(root, file, program, isDebug, splits);
									program.getDomainFile().moveTo(destination);
								}
							}
						}
					}
				}
			}
		}
		catch (CoffException e) {
			//TODO
		}
	}

	private DomainFolder establishFolder(DomainFolder root, File file, Program program,
			boolean isDebug, String[] splits) throws InvalidNameException, IOException {
		// very top is the root
		DomainFolder folder = root;

		// then comes architecture
		LanguageDescription description = program.getLanguage().getLanguageDescription();
		String arch =
			description.getProcessor() + "-" + description.getSize() + "-" +
				description.getEndian().toShortString();
		folder = obtainSubfolder(folder, arch);

		// then it's debug/non-debug
		String debuggishness = isDebug ? "debug" : "std";
		folder = obtainSubfolder(folder, debuggishness);

		// then it's the file path
		ArrayList<File> path = new ArrayList<File>();
		File current = file;
		path.add(current);
		while (current.getParentFile() != null) {
			path.add(current.getParentFile());
			current = current.getParentFile();
		}
		// -2 because the last element will be the root of the filesystem (empty)
		for (int ii = path.size() - 2; ii >= 0; --ii) {
			String entry = path.get(ii).getName();
			folder = obtainSubfolder(folder, entry);
		}

		// then it's the rest of the splits, minus the last one
		for (int ii = 0; ii < splits.length - 1; ++ii) {
			String entry = splits[ii];
			if ("..".equals(entry)) {
				continue;
			}
			folder = obtainSubfolder(folder, splits[ii]);
		}

		return folder;
	}

	private DomainFolder obtainSubfolder(DomainFolder parent, String child)
			throws InvalidNameException, IOException {
		child = mangleNameBecauseDomainFoldersAreSoRetro(child);
		DomainFolder folder = parent.getFolder(child);
		if (folder == null) {
			folder = parent.createFolder(child);
		}
		return folder;
	}

	private String[] splitPreferredName(String preferredName) {
		String[] splits = preferredName.split("[/\\\\]");
		return splits;
	}

//	private DomainFolder formLibraryPath(DomainFolder root, String directoryPath, File file)
//			throws InvalidNameException, IOException {
//		String filePath = file.getAbsolutePath();
//		String rest = filePath.substring(directoryPath.length() + 1);
//		Pair<DomainFolder, String> pair = establishProgramFolder(root, rest);
//		DomainFolder folder =
//			pair.first.createFolder(mangleNameBecauseDomainFoldersAreSoRetro(pair.second));
//		return folder;
//	}
//
//	private Pair<DomainFolder, String> establishProgramFolder(DomainFolder current,
//			String preferredName) throws InvalidNameException, IOException {
//		String[] splits = preferredName.split("[/\\\\]");
//		for (int ii = 0; ii < splits.length - 1; ++ii) {
//			String nextName = splits[ii];
//			DomainFolder next = current.getFolder(nextName);
//			if (next == null) {
//				next = current.createFolder(mangleNameBecauseDomainFoldersAreSoRetro(nextName));
//			}
//			current = next;
//		}
//		return new Pair<DomainFolder, String>(current, splits[splits.length - 1]);
//	}

	private String mangleNameBecauseDomainFoldersAreSoRetro(String name) {
		if (name == null) {
			return "(NULL)";
		}
		if (name.equals("")) {
			return "(EMPTY)";
		}
		StringBuilder sb = new StringBuilder();
		char[] charArray = name.toCharArray();
		for (char c : charArray) {
			if (!LocalFileSystem.isValidNameCharacter(c)) {
				c = '_';
			}
			sb.append(c);
		}
		return sb.toString();
	}

	private void findFiles(ArrayList<File> non_debug_files, ArrayList<File> debug_files,
			ArrayList<File> directories) throws CancelledException {
		for (File directory : directories) {
			monitor.checkCanceled();
			findFiles(non_debug_files, debug_files, directory);
		}
	}

	private void findFiles(ArrayList<File> non_debug_files, ArrayList<File> debug_files,
			File directory) throws CancelledException {
		ArrayList<File> subdirs = new ArrayList<File>();
		ArrayList<File> my_non_debug = new ArrayList<File>();
		ArrayList<File> my_debug = new ArrayList<File>();
		File[] files = directory.listFiles();

		if (files != null) {
			for (File file : files) {
				monitor.checkCanceled();
				if (file.isFile()) {
					String lowerName = file.getName().toLowerCase();
					if (lowerName.endsWith("d.lib")) {
						my_debug.add(file);
					}
					else if (lowerName.endsWith(".lib")) {
						my_non_debug.add(file);
					}
				}
				else if (file.isDirectory()) {
					subdirs.add(file);
				}
			}
		}

		for (File file : my_debug) {
			monitor.checkCanceled();
			String lowerName = file.getName().toLowerCase();
			String non_debug_name = lowerName.substring(0, lowerName.length() - 5) + ".lib";
			boolean notfound = true;
			int ii = 0;
			while (notfound && ii < my_non_debug.size()) {
				File non_debug = my_non_debug.get(ii);
				if (non_debug.getName().toLowerCase().equals(non_debug_name)) {
					notfound = false;
				}
				++ii;
			}
			if (notfound) {
				non_debug_files.add(file);
			}
			else {
				debug_files.add(file);
			}
		}

		non_debug_files.addAll(my_non_debug);

		for (File subdir : subdirs) {
			monitor.checkCanceled();
			findFiles(non_debug_files, debug_files, subdir);
		}
	}
}
