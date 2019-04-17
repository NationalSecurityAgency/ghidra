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
// Companion script to MSLibBatchImportGenerator.
//
// This script polls a directory on the file system for files queued there by the generator
// and imports the single file specified in each queue control file that it processes.
// Multiple instances of this script can run against the same work queue
// directory.
//
// This script will exit when its input queue is empty for several seconds.
//
// Queue internals:
//
// __queuebasedir/
// ____new/
// ____work/
// ____done/
//
// This scripts polls the "new" directory, grabs a single file and tries to move it 
// (using filesystem level atomic move/rename) to the "work" directory.  If that succeeds,
// the information in the queue file is used to perform an import operation.
// When the import operation is finished, the queue file is moved from the "work" directory
// to the "done" directory.
//
// To rerun the import process, simply move all the files from the "done" directory back
// to the "new" directory after resetting your project.
//
// If a script instance dies while importing a file, the troublesome binary's queue
// control file will be left in the "work" directory.  The user can move it back to
// the "new" directory (it will probably need renaming to remove some script metadata 
// from the filename) to re-submit the binary for processing.
//
// Example usage with analyzeHeadless:
//
// ./analyzeHeadless "ghidra://localhost/myproject" -preScript MSLibBatchImportWorker.java
//
//@category FunctionID

import java.io.File;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.*;
import java.util.function.Predicate;

import org.apache.commons.io.FileUtils;

import generic.stl.Pair;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.coff.*;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveHeader;
import ghidra.app.util.bin.format.coff.archive.CoffArchiveMemberHeader;
import ghidra.app.util.importer.*;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class MSLibBatchImportWorker extends GhidraScript {
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

	private static String getProcessId(String fallback) {
		// something like '<pid>@<hostname>', at least in SUN / Oracle JVMs
		String jvmName = ManagementFactory.getRuntimeMXBean().getName();
		int index = jvmName.indexOf('@');

		if (index > 0) {
			try {
				return Long.toString(Long.parseLong(jvmName.substring(0, index)));
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}

		return fallback;
	}

	String pid = getProcessId("fakepid_" + System.currentTimeMillis());

	String initalCheckInComment = "Initial import";

	@Override
	protected void run() throws Exception {
		// If running this via 'HeadlessAnalyzer', a MSLibBatchImportWorker.properties 
		// file needs to be created with a single line specifying the queue directory:
		// "Choose queue directory Choose=/path/to/queue/dir"
		// (without any quotes)
		// Which corresponds to the askDirectory() prompt in the next line:
		File directory = askDirectory("Choose queue directory", "Choose");
		// or the value could be hard-coded:
		// File directory = new File("/path/to/queue/dir");

		File newDir = new File(directory, "new");
		File workDir = new File(directory, "work");
		File doneDir = new File(directory, "done");
		newDir.mkdir();
		workDir.mkdir();
		doneDir.mkdir();

		int totalFilesProcessed = 0;
		long lastWorkTS = System.currentTimeMillis();
		int maxIdleMS = 10 * 1000;

		while ((System.currentTimeMillis() - lastWorkTS) < maxIdleMS) {
			if (monitor.isCancelled()) {
				break;
			}

			int filesProcessed = 0;

			Iterator<File> files = FileUtils.iterateFiles(newDir, null, false);
			while (files.hasNext()) {

				File newFile = files.next();

				File workFile = new File(workDir, ".work_" + pid + "_" + newFile.getName());
				if (!newFile.renameTo(workFile)) {
					continue;
				}
				workFile.setLastModified(System.currentTimeMillis());

				List<String> lines = FileUtilities.getLines(workFile);
				if (lines.size() != 2) {
					println("Found bad file: " + workFile);
					continue;
				}
				String importFilePath = lines.get(0);
				String destFolderPath = lines.get(1);

				File importFile = new File(importFilePath);
				if (!importFile.exists()) {
					println("Can not find import file: " + importFile);
					continue;
				}
				DomainFolder destFolder = getFolder(
					state.getProject().getProjectData().getRootFolder(), destFolderPath, true);
				MessageLog log = new MessageLog();
				importLibrary(destFolder, importFile, log);

				File doneFile = new File(doneDir, newFile.getName());
				if (!workFile.renameTo(doneFile)) {
					throw new IOException("Failed to move " + workFile + " to " + doneFile);
				}
				doneFile.setLastModified(System.currentTimeMillis());

				filesProcessed++;
				totalFilesProcessed++;
			}
			lastWorkTS = (filesProcessed != 0) ? System.currentTimeMillis() : lastWorkTS;

			Thread.sleep(500);
		}
		println("Exiting import wait loop, total files processed: " + totalFilesProcessed);
	}

	private void importLibrary(DomainFolder currentLibraryFolder, File file, MessageLog log)
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
								getFolderAndUniqueFile(currentLibraryFolder, preferredName);

							List<Program> programs = AutoImporter.importFresh(coffProvider,
								pair.first, this, log, monitor, LOADER_FILTER, LOADSPEC_CHOOSER,
								pair.second, OptionChooser.DEFAULT_OPTIONS,
								MultipleProgramsStrategy.ONE_PROGRAM_OR_EXCEPTION);

							if (programs != null) {
								for (Program program : programs) {
									println("Imported " + program.getDomainFile().getPathname());
									DomainFile progFile = program.getDomainFile();

									program.release(this);

									if (!progFile.isVersioned()) {
										progFile.addToVersionControl(initalCheckInComment, false,
											monitor);
									}

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

	private static DomainFolder getFolder(DomainFolder folder, String path,
			boolean createIfMissing) throws InvalidNameException, IOException {
		for (String pathpart : path.split("[/\\\\]")) {
			if (pathpart.isEmpty()) {
				continue;
			}
			pathpart = ensureSafeProjectObjName(pathpart);
			DomainFolder tmp = folder.getFolder(pathpart);
			if (tmp == null) {
				if (!createIfMissing) {
					return null;
				}
				tmp = folder.createFolder(pathpart);
			}
			folder = tmp;
		}
		return folder;
	}

	private static Pair<DomainFolder, String> getFolderAndUniqueFile(DomainFolder current,
			String preferredName) throws InvalidNameException, IOException {
		
		int pathSepIndex;
		for(pathSepIndex = preferredName.length() - 1; pathSepIndex >= 0; pathSepIndex--) {
			if ( "/\\".indexOf(preferredName.charAt(pathSepIndex)) != -1 ) {
				break;
			}
		}
		String folderStr = (pathSepIndex >= 0) ? preferredName.substring(0, pathSepIndex) : "";
		String fileStr = ensureSafeProjectObjName(preferredName.substring(pathSepIndex + 1));

		DomainFolder folder = getFolder(current, folderStr, true);
		return new Pair<DomainFolder, String>(folder, getUniqueDomainFileName(folder, fileStr));
	}

	private static String ensureSafeProjectObjName(String name) {
		switch (name) {
			case ".":
				return "dot";
			case "..":
				return "dotdot";
		}

		StringBuilder sb = new StringBuilder();
		for (char c : name.toCharArray()) {
			sb.append(LocalFileSystem.isValidNameCharacter(c) ? c : '_');
		}
		return sb.toString();
	}

	private static String getUniqueDomainFileName(DomainFolder folder, String baseName) {
		int highestNum = -1;
		for (DomainFile domainFile : folder.getFiles()) {
			String fname = domainFile.getName();
			if (fname.startsWith(baseName)) {
				String suffix = fname.substring(baseName.length());
				if (suffix.isEmpty()) {
					highestNum = Math.max(0, highestNum);
				}
				else if (suffix.matches("^[1-9][0-9]*")) {
					try {
						int val = Integer.parseInt(suffix);
						highestNum = Math.max(val, highestNum);
					}
					catch (NumberFormatException nfe) {
						// ignore
					}
				}
			}
		}
		return (highestNum == -1) ? baseName : String.format("%s%d", baseName, highestNum + 1);
	}

}

