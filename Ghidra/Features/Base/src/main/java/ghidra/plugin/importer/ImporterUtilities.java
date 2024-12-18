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
package ghidra.plugin.importer;

import java.awt.Window;
import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.help.AboutDomainObjectUtils;
import ghidra.app.services.FileSystemBrowserService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.FileBytesProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Utilities for importing files.
 * 
 * <p>Note: if a method takes a {@link TaskMonitor}, then that method should only be called 
 * from a background task.
 */
public class ImporterUtilities {

	/**
	 * File extension filter for well known 'loadable' files for GhidraFileChoosers.
	 */
	public static final GhidraFileFilter LOADABLE_FILES_FILTER = ExtensionFileFilter.forExtensions(
		"Loadable files", "exe", "dll", "obj", "drv", "bin", "hex", "o", "a", "so", "class", "lib",
		"dylib");

	/**
	 * File extension filter for well known 'container' files for GhidraFileChoosers.
	 */
	public static final GhidraFileFilter CONTAINER_FILES_FILTER =
		ExtensionFileFilter.forExtensions("Container files", "zip", "tar", "tgz", "jar", "gz",
			"ipsw", "img3", "dmg", "apk", "cpio", "rpm", "lib");

	private static final FileSystemService fsService = FileSystemService.getInstance();

	static List<LanguageCompilerSpecPair> getPairs(Collection<LoadSpec> loadSpecs) {
		Set<LanguageCompilerSpecPair> pairs = new HashSet<>();
		for (LoadSpec loadSpec : loadSpecs) {
			LanguageCompilerSpecPair pair = loadSpec.getLanguageCompilerSpec();
			if (pair != null) {
				pairs.add(pair);
			}
		}
		return CollectionUtils.asList(pairs);
	}

	/**
	 * Displays the appropriate import dialog for the specified {@link FSRL file}.
	 * <p>
	 * If the file is a container of other files, a batch import dialog will be used,
	 * otherwise the normal single file import dialog will be shown.
	 *
	 * @param tool {@link PluginTool} will be used as the parent tool for dialogs
	 * @param programManager optional {@link ProgramManager} instance to use to open imported 
	 * 			binaries with, or null
	 * @param fsrl {@link FSRL} of the file to import
	 * @param destinationFolder {@link DomainFolder} destination folder where the imported file
	 * 			will default to.  (the user will be able to choose a different location)
	 * @param suggestedPath optional string path that will automatically be pre-pended
	 * 			to the destination filename
	 */
	public static void showImportDialog(PluginTool tool, ProgramManager programManager, FSRL fsrl,
			DomainFolder destinationFolder, String suggestedPath) {

		TaskLauncher.launchModal("Import", monitor -> {
			showImportDialog(tool, programManager, fsrl, destinationFolder, suggestedPath, monitor);
		});
	}

	/**
	 * Displays the appropriate import dialog for the specified {@link FSRL file}.
	 * <p>
	 * If the file is a container of other files, a batch import dialog will be used,
	 * otherwise the normal single file import dialog will be shown.]
	 * <p>
	 * If you are not in a monitored task, then call 
	 * {@link #showImportDialog(PluginTool, ProgramManager, FSRL, DomainFolder, String)}.
	 *
	 * @param tool {@link PluginTool} will be used as the parent tool for dialogs
	 * @param programManager optional {@link ProgramManager} instance to use to open imported 
	 * 			binaries with, or null
	 * @param fsrl {@link FSRL} of the file to import
	 * @param destinationFolder {@link DomainFolder} destination folder where the imported file
	 * 			will default to.  (the user will be able to choose a different location)
	 * @param suggestedPath optional string path that will automatically be pre-pended
	 * 			to the destination filename
	 * @param monitor the task monitor to use for monitoring; cannot be null
	 */
	public static void showImportDialog(PluginTool tool, ProgramManager programManager, FSRL fsrl,
			DomainFolder destinationFolder, String suggestedPath, TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		RefdFile referencedFile = null;
		try {
			referencedFile = fsService.getRefdFile(fsrl, monitor);

			FSRL fullFsrl = fsService.getFullyQualifiedFSRL(fsrl, monitor);
			boolean isFSContainer = fsService.isFileFilesystemContainer(fullFsrl, monitor);
			if (referencedFile.file.getLength() == 0) {
				Msg.showError(ImporterUtilities.class, null, "File is empty",
					"File " + fsrl.getPath() + " is empty, nothing to import");
				return;
			}

			GFileSystem fs = referencedFile.fsRef.getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				doFsImport(referencedFile, fullFsrl, destinationFolder, programManager, tool);
				return;
			}

			if (!isFSContainer) {
				// normal file; do a single-file import
				showImportSingleFileDialog(fullFsrl, destinationFolder, suggestedPath, tool,
					programManager, monitor);
				return;
			}

			// file is a container, ask user to pick single import, batch import or fs browser
			importFromContainer(tool, programManager, destinationFolder, suggestedPath, monitor,
				referencedFile, fullFsrl);
		}
		catch (IOException ioe) {
			String message = ioe.getMessage();
			Msg.showError(ImporterUtilities.class, null, "Import Error", "Unable to import file " +
				fsrl.getName() + (message != null ? ("\n\nCause: " + message) : ""), ioe);
		}
		catch (CancelledException e) {
			Msg.info(ImporterUtilities.class, "Show Import Dialog canceled");
		}
		finally {
			close(referencedFile);
		}
	}

	private static void close(Closeable c) {
		if (c != null) {
			try {
				c.close();
			}
			catch (IOException e) {
				// ignore
			}
		}
	}

	private static void importFromContainer(PluginTool tool, ProgramManager programManager,
			DomainFolder destinationFolder, String suggestedPath, TaskMonitor monitor,
			RefdFile referencedFile, FSRL fullFsrl) {

		Window parent = tool.getActiveWindow();
		FileSystemBrowserService fsbService = tool.getService(FileSystemBrowserService.class);
		int choice = 0; // cancelled
		if (fsbService == null) {

			//@formatter:off
			choice = OptionDialog.showOptionDialog(parent, "Container File Detected",
				"The file " + referencedFile.file.getName() +
					" seems to have nested files in it.  Select an import mode:",							
				"Single file",  // 1 
				"Batch", 		// 2
				OptionDialog.QUESTION_MESSAGE);
		}
		else {
			choice = OptionDialog.showOptionDialog(parent, "Container File Detected",
				"The file " + referencedFile.file.getName() +
					" seems to have nested files in it.  Select an import mode:",							
				"Single file",  // 1 
				"Batch", 		// 2						
				"File System", 	// 3
				OptionDialog.QUESTION_MESSAGE);
			//@formatter:on
		}

		if (choice == 1) {
			showImportSingleFileDialog(fullFsrl, destinationFolder, suggestedPath, tool,
				programManager, monitor);
		}
		else if (choice == 2) {
			BatchImportDialog.showAndImport(tool, null, List.of(fullFsrl), destinationFolder,
				programManager);
		}
		else if (choice == 3) {
			fsbService.openFileSystem(fullFsrl);
		}
	}

	public static void showAddToProgramDialog(FSRL fsrl, Program program, PluginTool tool,
			TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		// Don't allow Add To Program while "things are happening" to the program
		if (!program.canLock()) {
			Msg.showWarn(null, null, "Add To Program",
				"Cannot Add To Program while program is locked.  Please wait or stop running tasks.");
			return;
		}

		try {
			ByteProvider provider = fsService.getByteProvider(fsrl, false, monitor);
			if (provider.length() == 0) {
				Msg.showWarn(null, null, "Error opening " + fsrl.getName(),
					"The item does not correspond to a valid file.");
				provider.close();
				return;
			}

			LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(provider,
				loader -> loader.supportsLoadIntoProgram(program));

			SystemUtilities.runSwingLater(() -> {
				AddToProgramDialog dialog =
					new AddToProgramDialog(tool, fsrl, loaderMap, provider, program);
				tool.showDialog(dialog);
			});
		}
		catch (IOException e) {
			Msg.showError(ImporterUtilities.class, null, "Error Reading Resource",
				"I/O error reading " + fsrl.getName(), e);
		}
		catch (CancelledException e) {
			// just return
		}

	}

	public static void showLoadLibrariesDialog(Program program, PluginTool tool,
			ProgramManager manager, TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		// Don't allow Load Libraries while "things are happening" to the program
		if (!program.canLock()) {
			Msg.showWarn(null, null, LoadLibrariesOptionsDialog.TITLE,
				"Cannot Load Libraries while program is locked.  Please wait or stop running tasks.");
			return;
		}

		try {
			ByteProvider provider = getProvider(program);
			LoadSpec loadSpec = getLoadSpec(provider, program);
			AddressFactory addressFactory =
				loadSpec.getLanguageCompilerSpec().getLanguage().getAddressFactory();
			SystemUtilities.runSwingLater(() -> {
				OptionsDialog dialog = new LoadLibrariesOptionsDialog(provider, program, tool,
					loadSpec, () -> addressFactory);
				tool.showDialog(dialog);
			});
		}
		catch (LanguageNotFoundException e) {
			Msg.showError(null, null, LoadLibrariesOptionsDialog.TITLE, "Language not found.", e);
		}
	}

	/**
	 * Constructs a {@link ImporterDialog} and shows it in the swing thread.
	 * 
	 *
	 * @param fsrl the file system resource locater (can be a simple file or an element of
	 * 			a more complex file such as a zip file)
	 * @param destinationFolder the default destination folder for the imported file. Can be null
	 * @param suggestedPath optional string path that will automatically be pre-pended
	 * 			to the destination filename
	 * @param tool the parent UI component
	 * @param programManager optional {@link ProgramManager} instance to open the imported file in
	 * @param monitor {@link TaskMonitor}
	 */
	public static void showImportSingleFileDialog(FSRL fsrl, DomainFolder destinationFolder,
			String suggestedPath, PluginTool tool, ProgramManager programManager,
			TaskMonitor monitor) {

		try {
			ByteProvider provider = fsService.getByteProvider(fsrl, true, monitor);
			LoaderMap loaderMap = LoaderService.getAllSupportedLoadSpecs(provider);

			SystemUtilities.runSwingLater(() -> {
				ImporterDialog importerDialog = new ImporterDialog(tool, programManager, loaderMap,
					provider, suggestedPath);
				if (destinationFolder != null) {
					importerDialog.setDestinationFolder(destinationFolder);
				}

				tool.showDialog(importerDialog);
			});
		}
		catch (IOException ioe) {
			Msg.showError(ImporterUtilities.class, tool.getActiveWindow(), "Error Importing File",
				"Error when importing file " + fsrl, ioe);
		}
		catch (CancelledException e) {
			Msg.info(ImporterUtilities.class, "Import single file " + fsrl + " cancelled");
		}
	}

	private static void doFsImport(RefdFile refdFile, FSRL fsrl, DomainFolder destFolderParam,
			ProgramManager programManager, PluginTool tool) {
		TaskLauncher.launchNonModal("Import File (FileSystem specific)", monitor -> {
			GFile gfile = refdFile.file;
			try {
				Object consumer = new Object();
				DomainFolder destFolder = (destFolderParam == null)
						? AppInfo.getActiveProject().getProjectData().getRootFolder()
						: destFolderParam;
				Program program =
					doFSImportHelper((GFileSystemProgramProvider) refdFile.fsRef.getFilesystem(),
						gfile, destFolder, consumer, monitor);
				if (program != null) {
					LoadResults<? extends DomainObject> loadResults = new LoadResults<>(program,
						program.getName(), destFolder.getPathname());
					boolean success = false;
					try {
						doPostImportProcessing(tool, programManager, fsrl, loadResults, consumer,
							"", monitor);
						success = true;
					}
					finally {
						if (!success) {
							program.release(consumer);
						}
					}
				}
			}
			catch (Exception e) {
				FSUtilities.displayException(ImporterUtilities.class, tool.getActiveWindow(),
					"Problem Encountered During Import",
					"Unable to import file " + refdFile.file.getName() +
						" using special purpose loader built into the " +
						gfile.getFilesystem().getDescription() + " filesystem.",
					e);
			}
		});
	}

	private static Program doFSImportHelper(GFileSystemProgramProvider pfs, GFile gfile,
			DomainFolder destFolder, Object consumer, TaskMonitor monitor) throws Exception {
		Program program =
			pfs.getProgram(gfile, DefaultLanguageService.getLanguageService(), monitor, consumer);

		if (program == null) {
			return null;
		}

		boolean success = false;
		try {
			String importFilename = ProjectDataUtils.getUniqueName(destFolder, program.getName());
			if (importFilename == null) {
				throw new IOException("Unable to find unique name for " + program.getName());
			}
			destFolder.createFile(importFilename, program, monitor);
			success = true;
			return program;
		}
		finally {
			if (!success) {
				program.release(consumer);
			}
		}

	}

	/**
	 * Perform file import and open using optional programManager
	 * @param tool tool to which popup dialogs should be associated
	 * @param programManager program manager to open imported file with or null
	 * @param fsrl import file location
	 * @param destFolder project destination folder
	 * @param loadSpec import {@link LoadSpec}
	 * @param programName program name
	 * @param options import options
	 * @param monitor task monitor
	 */
	public static void importSingleFile(PluginTool tool, ProgramManager programManager, FSRL fsrl,
			DomainFolder destFolder, LoadSpec loadSpec, String programName, List<Option> options,
			TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		try (ByteProvider bp = fsService.getByteProvider(fsrl, false, monitor)) {

			Object consumer = new Object();
			MessageLog messageLog = new MessageLog();
			LoadResults<? extends DomainObject> loadResults = loadSpec.getLoader()
					.load(bp, programName, tool.getProject(), destFolder.getPathname(), loadSpec,
						options, messageLog, consumer, monitor);

			loadResults.save(tool.getProject(), consumer, messageLog, monitor);

			doPostImportProcessing(tool, programManager, fsrl, loadResults, consumer,
				messageLog.toString(), monitor);
		}
		catch (CancelledException e) {
			// no need to show a message
		}
		catch (Exception e) {
			Msg.showError(ImporterUtilities.class, tool.getActiveWindow(), "Error Importing File",
				"Error importing file: " + fsrl.getName(), e);
		}
	}

	private static Set<DomainFile> doPostImportProcessing(PluginTool pluginTool,
			ProgramManager programManager, FSRL fsrl,
			LoadResults<? extends DomainObject> loadResults, Object consumer, String importMessages,
			TaskMonitor monitor) throws CancelledException {

		boolean firstProgram = true;
		Set<DomainFile> importedFilesSet = new HashSet<>();
		for (Loaded<? extends DomainObject> loaded : loadResults) {
			monitor.checkCancelled();

			if (loaded.getDomainObject() instanceof Program program) {
				if (programManager != null) {
					int openState = firstProgram
							? ProgramManager.OPEN_CURRENT
							: ProgramManager.OPEN_VISIBLE;
					programManager.openProgram(program, openState);
				}
				importedFilesSet.add(program.getDomainFile());
			}
			if (firstProgram) {
				// currently we only show results for the imported program, not any libraries
				displayResults(pluginTool, loaded.getDomainObject(),
					loaded.getDomainObject().getDomainFile(), importMessages);

				// Optionally echo loader message log to application.log
				if (!Loader.loggingDisabled && !importMessages.isEmpty()) {
					Msg.info(ImporterUtilities.class, "Additional info:\n" + importMessages);
				}
			}
			loaded.release(consumer);
			firstProgram = false;
		}

		selectFiles(importedFilesSet);
		return importedFilesSet;
	}

	private static void selectFiles(Set<DomainFile> importedFilesSet) {
		FrontEndTool frontEndTool = AppInfo.getFrontEndTool();
		if (frontEndTool != null) {
			frontEndTool.selectFiles(importedFilesSet);
		}
	}

	public static void addContentToProgram(PluginTool tool, Program program, FSRL fsrl,
			LoadSpec loadSpec, List<Option> options, TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		MessageLog messageLog = new MessageLog();
		try (ByteProvider bp = fsService.getByteProvider(fsrl, false, monitor)) {
			loadSpec.getLoader().loadInto(bp, loadSpec, options, messageLog, program, monitor);
			displayResults(tool, program, program.getDomainFile(), messageLog.toString());

			// Optionally echo loader message log to application.log
			if (!Loader.loggingDisabled && messageLog.hasMessages()) {
				Msg.info(ImporterUtilities.class, "Additional info:\n" + messageLog.toString());
			}
		}
		catch (CancelledException e) {
			return;
		}
		catch (IOException e) {
			Msg.showError(ImporterUtilities.class, null, "Error Importing File",
				"Error importing file " + fsrl.getName(), e);
		}

	}

	private static void displayResults(PluginTool tool, DomainObject obj, DomainFile df,
			String info) {

		DomainFile domainFile = obj.getDomainFile();
		Map<String, String> metadata = obj.getMetadata();
		if (df != null) {
			domainFile = df;
			metadata = df.getMetadata();
		}

		HelpLocation helpLocation = new HelpLocation(GenericHelpTopics.ABOUT, "About_Program");
		AboutDomainObjectUtils.displayInformation(tool, domainFile, metadata,
			"Import Results Summary", info, helpLocation);
	}

	/**
	 * Gets a {@link ByteProvider} based on the {@link FileBytes} of the given {@link Program}.
	 * <p>
	 * NOTE: If the {@link Program} has more than one {@link FileBytes} associated with it, the
	 * first one is used (this is typically the bytes of the originally imported file).
	 * 
	 * @param program The {@link Program}
	 * @return A {@link ByteProvider} based on the {@link FileBytes} of the given {@link Program},
	 *   or null if the {@link Program} doesn't have an associated {@link FileBytes}
	 */
	static ByteProvider getProvider(Program program) {
		List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
		return !allFileBytes.isEmpty() ? new FileBytesProvider(allFileBytes.get(0)) : null;
	}

	/**
	 * Get's the {@link LoadSpec} that was used to import the given {@link Program}
	 * 
	 * @param provider The original bytes of the {@link Program}
	 * @param program The {@link Program}
	 * @return The {@link LoadSpec} that was used to import the given {@link Program}, or null if
	 *   it could not be determined
	 */
	static LoadSpec getLoadSpec(ByteProvider provider, Program program) {
		LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(provider,
			loader -> loader.getName().equalsIgnoreCase(program.getExecutableFormat()));

		if (loaderMap.isEmpty()) {
			return null;
		}

		Loader loader = loaderMap.firstKey();
		if (loader == null) {
			return null;
		}

		LanguageCompilerSpecPair programLcs = program.getLanguageCompilerSpecPair();
		return loaderMap.get(loader)
				.stream()
				.filter(e -> programLcs.equals(e.getLanguageCompilerSpec()))
				.findFirst()
				.orElse(null);
	}
}
