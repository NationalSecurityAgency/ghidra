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

import java.util.*;

import java.awt.Window;
import java.io.Closeable;
import java.io.IOException;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.help.AboutDomainObjectUtils;
import ghidra.app.services.FileSystemBrowserService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.GenericHelpTopics;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.plugins.importer.batch.BatchImportDialog;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
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
	 *
	 * TODO: will be refactored to use file_extension_icon.xml file info.
	 */
	public static final GhidraFileFilter LOADABLE_FILES_FILTER = ExtensionFileFilter.forExtensions(
		"Loadable files", "exe", "dll", "obj", "drv", "bin", "o", "a", "so", "class", "lib");

	/**
	 * File extension filter for well known 'container' files for GhidraFileChoosers.
	 *
	 * TODO: will be refactored to use file_extension_icon.xml file info.
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
	 * Ensure that a {@link Program}'s metadata includes its import origin.
	 *
	 * @param program imported {@link Program} to modify
	 * @param fsrl {@link FSRL} of the import source.
	 * @param monitor {@link TaskMonitor} to use when accessing filesystem stuff.
	 * @throws CancelledException if user cancels
	 * @throws IOException if IO error
	 */
	public static void setProgramProperties(Program program, FSRL fsrl, TaskMonitor monitor)
			throws CancelledException, IOException {

		Objects.requireNonNull(monitor);

		int id = program.startTransaction("setImportProperties");
		try {
			fsrl = fsService.getFullyQualifiedFSRL(fsrl, monitor);

			Options propertyList = program.getOptions(Program.PROGRAM_INFO);
			if (!propertyList.contains(ProgramMappingService.PROGRAM_SOURCE_FSRL)) {
				propertyList.setString(ProgramMappingService.PROGRAM_SOURCE_FSRL, fsrl.toString());
			}
			String md5 = program.getExecutableMD5();
			if ((md5 == null || md5.isEmpty()) && fsrl.getMD5() != null) {
				program.setExecutableMD5(fsrl.getMD5());
			}
		}
		finally {
			program.endTransaction(id, true);
		}
		if (program.canSave()) {
			program.save("Added import properties", monitor);
		}
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
				importSingleFile(fullFsrl, destinationFolder, suggestedPath, tool, programManager,
					monitor);
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
			importSingleFile(fullFsrl, destinationFolder, suggestedPath, tool, programManager,
				monitor);
		}
		else if (choice == 2) {
			BatchImportDialog.showAndImport(tool, null, Arrays.asList(fullFsrl), destinationFolder,
				programManager);
		}
		else if (choice == 3) {
			fsbService.openFileSystem(fullFsrl);
		}
	}

	public static void showAddToProgramDialog(FSRL fsrl, Program program, PluginTool tool,
			TaskMonitor monitor) {

		Objects.requireNonNull(monitor);

		try {
			ByteProvider provider = fsService.getByteProvider(fsrl, false, monitor);
			if (provider.length() == 0) {
				Msg.showWarn(null, null, "Error opening " + fsrl.getName(),
					"The item does not correspond to a valid file.");
				provider.close();
				return;
			}

			LoaderMap loaderMap = LoaderService.getSupportedLoadSpecs(provider,
				loader -> loader.supportsLoadIntoProgram());

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
	 */
	private static void importSingleFile(FSRL fsrl, DomainFolder destinationFolder,
			String suggestedPath, PluginTool tool, ProgramManager programManager,
			TaskMonitor monitor) {

		try {
			ByteProvider provider = fsService.getByteProvider(fsrl, true, monitor);
			LoaderMap loaderMap = LoaderService.getAllSupportedLoadSpecs(provider);

			SystemUtilities.runSwingLater(() -> {
				ImporterDialog importerDialog =
					new ImporterDialog(tool, programManager, loaderMap, provider, suggestedPath);
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
					doPostImportProcessing(tool, programManager, fsrl, Arrays.asList(program),
						consumer, "", monitor);
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

		if (program != null) {
			String importFilename = ProjectDataUtils.getUniqueName(destFolder, program.getName());
			if (importFilename == null) {
				program.release(consumer);
				throw new IOException("Unable to find unique name for " + program.getName());
			}

			destFolder.createFile(importFilename, program, monitor);
		}
		return program;

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
			List<DomainObject> importedObjects = loadSpec.getLoader().load(bp, programName,
				destFolder, loadSpec, options, messageLog, consumer, monitor);
			if (importedObjects == null) {
				return;
			}

			doPostImportProcessing(tool, programManager, fsrl, importedObjects, consumer,
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
			ProgramManager programManager, FSRL fsrl, List<DomainObject> importedObjects,
			Object consumer, String importMessages, TaskMonitor monitor)
			throws CancelledException, IOException {

		boolean firstProgram = true;
		Set<DomainFile> importedFilesSet = new HashSet<>();
		for (DomainObject importedObject : importedObjects) {
			monitor.checkCanceled();

			if (importedObject instanceof Program) {
				Program program = (Program) importedObject;

				setProgramProperties(program, fsrl, monitor);
				ProgramMappingService.createAssociation(fsrl, program);

				if (programManager != null) {
					int openState =
						firstProgram ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE;
					programManager.openProgram(program, openState);
				}
				importedFilesSet.add(program.getDomainFile());
			}
			if (firstProgram) {
				// currently we only show results for the imported program, not any libraries
				displayResults(pluginTool, importedObject, importedObject.getDomainFile(),
					importMessages);
			}
			importedObject.release(consumer);
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
}
