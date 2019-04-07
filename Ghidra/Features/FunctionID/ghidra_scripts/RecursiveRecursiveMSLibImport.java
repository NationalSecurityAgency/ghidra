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
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class RecursiveRecursiveMSLibImport extends GhidraScript {
	final static Predicate<Loader> LOADER_FILTER = new SingleLoaderFilter(MSCoffLoader.class);
	final static LoadSpecChooser LOADSPEC_CHOOSER = new LoadSpecChooser() {
		@Override
		public LoadSpec choose(List<LoadSpec> loadSpecs) {
			for (LoadSpec loadSpec : loadSpecs) {
				LanguageCompilerSpecPair lcsp = loadSpec.getLanguageCompilerSpec();
				if (lcsp.compilerSpecID.getIdAsString().equals("windows")) {
					return loadSpec;
				}
			}
			for (LoadSpec loadSpec : loadSpecs) {
				LanguageCompilerSpecPair lcsp = loadSpec.getLanguageCompilerSpec();
				try {
					if (lcsp.getLanguageDescription().getEndian() == Endian.LITTLE &&
						lcsp.getLanguageDescription().getVariant().contains("v7")) {
						return loadSpec;
					}
				}
				catch (LanguageNotFoundException e) {
					// ignore...not sure why this happened
				}
			}
			for (LoadSpec loadSpec : loadSpecs) {
				LanguageCompilerSpecPair lcsp = loadSpec.getLanguageCompilerSpec();
				if (lcsp.compilerSpecID.getIdAsString().equals("gcc")) {
					return loadSpec;
				}
			}
			return null;
		}

		@Override
		public boolean usePreferred() {
			return true;
		}
	};

	@Override
	protected void run() throws Exception {
		DomainFolder non_debug_root =
			askProjectFolder("Choose a top-level domain folder for NON-DEBUG libraries");
		DomainFolder debug_root =
			askProjectFolder("Choose a top-level domain folder for DEBUG libraries");

		// ALL .LIB files under this directory will be inspected/imported as Win COFF
		File directory = askDirectory("Choose the top-level import directory", "Choose");
		String directoryPath = directory.getAbsolutePath();

		ArrayList<File> non_debug_files = new ArrayList<File>();
		ArrayList<File> debug_files = new ArrayList<File>();

		findFiles(non_debug_files, debug_files, directory);

		for (File file : non_debug_files) {
			MessageLog log = new MessageLog();
			importLibrary(formLibraryPath(non_debug_root, directoryPath, file), file, log);
		}

		for (File file : debug_files) {
			MessageLog log = new MessageLog();
			importLibrary(formLibraryPath(debug_root, directoryPath, file), file, log);
		}
	}

	private void findFiles(ArrayList<File> non_debug_files, ArrayList<File> debug_files,
			File directory) {
		ArrayList<File> subdirs = new ArrayList<File>();
		ArrayList<File> my_non_debug = new ArrayList<File>();
		ArrayList<File> my_debug = new ArrayList<File>();
		File[] files = directory.listFiles();

		if (files != null) {
			for (File file : files) {
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
			findFiles(non_debug_files, debug_files, subdir);
		}
	}

	private DomainFolder formLibraryPath(DomainFolder root, String directoryPath, File file)
			throws InvalidNameException, IOException {
		String filePath = file.getAbsolutePath();
		String rest = filePath.substring(directoryPath.length() + 1);
		Pair<DomainFolder, String> pair = establishProgramFolder(root, rest);
		DomainFolder folder =
			pair.first.createFolder(mangleNameBecauseDomainFoldersAreSoRetro(pair.second));
		return folder;
	}

	private void importLibrary(DomainFolder currentLibrary, File file, MessageLog log)
			throws CancelledException, DuplicateNameException, InvalidNameException,
			VersionException, IOException {

		try (RandomAccessByteProvider provider = new RandomAccessByteProvider(file)) {
			if (!CoffArchiveHeader.isMatch(provider)) {
				return;
			}
			CoffArchiveHeader coffArchiveHeader =
				CoffArchiveHeader.read(provider, TaskMonitor.DUMMY);
			HashSet<Long> offsetsSeen = new HashSet<Long>();
			for (CoffArchiveMemberHeader archiveMemberHeader : coffArchiveHeader.getArchiveMemberHeaders()) {
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

							Pair<DomainFolder, String> pair =
								establishProgramFolder(currentLibrary, preferredName);

							List<Program> programs = AutoImporter.importFresh(coffProvider,
								pair.first, this, log, monitor, LOADER_FILTER, LOADSPEC_CHOOSER,
								mangleNameBecauseDomainFoldersAreSoRetro(pair.second),
								OptionChooser.DEFAULT_OPTIONS,
								MultipleProgramsStrategy.ONE_PROGRAM_OR_EXCEPTION);

							if (programs != null) {
								for (Program program : programs) {
									program.release(this);
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

	private Pair<DomainFolder, String> establishProgramFolder(DomainFolder current,
			String preferredName) throws InvalidNameException, IOException {
		String[] splits = preferredName.split("[/\\\\]");
		for (int ii = 0; ii < splits.length - 1; ++ii) {
			String nextName = splits[ii];
			DomainFolder next = current.getFolder(nextName);
			if (next == null) {
				next = current.createFolder(mangleNameBecauseDomainFoldersAreSoRetro(nextName));
			}
			current = next;
		}
		return new Pair<DomainFolder, String>(current, splits[splits.length - 1]);
	}

	private String mangleNameBecauseDomainFoldersAreSoRetro(String name) {
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
}
