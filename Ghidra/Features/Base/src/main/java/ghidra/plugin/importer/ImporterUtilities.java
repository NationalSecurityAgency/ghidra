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

import java.awt.Component;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.help.AboutDomainObjectUtils;
import ghidra.app.services.FileSystemBrowserService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.GenericHelpTopics;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
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
		int id = program.startTransaction("setImportProperties");
		try {
			fsrl = FileSystemService.getInstance().getFullyQualifiedFSRL(fsrl, monitor);

			Options propertyList = program.getOptions(Program.PROGRAM_INFO);
			propertyList.setString(ProgramMappingService.PROGRAM_SOURCE_FSRL, fsrl.toString());
			if ((program.getExecutableMD5() == null || program.getExecutableMD5().isEmpty()) &&
				fsrl.getMD5() != null) {
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
	 * <p>
	 *
	 * @param fsrl {@link FSRL} of the file to import.
	 * @param destFolder {@link DomainFolder} destination folder where the imported file
	 * will default to.  (the user will be able to choose a different location).
	 * @param suggestedDestinationPath optional string path that will automatically be pre-pended
	 * to the destination filename.
	 * @param tool {@link PluginTool} will be used as the parent tool for dialogs.
	 * @param programManager optional {@link ProgramManager} instance to use to open imported binaries with, or null.
	 */
	public static void showImportDialog(FSRL fsrl, DomainFolder destFolder,
			String suggestedDestinationPath, PluginTool tool, ProgramManager programManager) {

		Component parent = tool.getActiveWindow();
		AtomicReference<RefdFile> refdFile = new AtomicReference<>();
		AtomicReference<FSRL> fqFSRL = new AtomicReference<>();
		AtomicBoolean isFSContainer = new AtomicBoolean();
		AtomicBoolean success = new AtomicBoolean();
		try {
			// do IO stuff in separate thread, with no UI prompts
			TaskLauncher.launchModal("Import", (monitor) -> {
				try {
					RefdFile tmpRefdFile =
						FileSystemService.getInstance().getRefdFile(fsrl, monitor);
					refdFile.set(tmpRefdFile);

					FSRL tmpFQFSRL =
						FileSystemService.getInstance().getFullyQualifiedFSRL(fsrl, monitor);
					fqFSRL.set(tmpFQFSRL);

					isFSContainer.set(FileSystemService.getInstance().isFileFilesystemContainer(
						tmpFQFSRL, monitor));

					success.set(true);
				}
				catch (IOException ioe) {
					Msg.showError(ImporterUtilities.class, parent, "Import Error",
						"Unable to import file " + fsrl.getName() +
							(ioe.getMessage() != null ? ("\n\nCause: " + ioe.getMessage()) : ""),
						ioe);
				}
				catch (CancelledException e) {
					Msg.info(ImporterUtilities.class, "ShowImportDialog canceled");
				}
			});

			if (!success.get()) {
				return;
			}

			if (refdFile.get().file.getLength() == 0) {
				Msg.showError(ImporterUtilities.class, parent, "File is empty",
					"File " + fsrl.getPath() + " is empty, nothing to import");
				return;
			}

			GFileSystem fs = refdFile.get().fsRef.getFilesystem();
			if (fs instanceof GFileSystemProgramProvider) {
				doFSImport(refdFile.get(), fqFSRL.get(), destFolder, programManager, tool);
				return;
			}

			if (isFSContainer.get()) {
				// If file was a container,
				// allow the user to pick between single import, batch import and fs browser
				FileSystemBrowserService fsbService =
					tool.getService(FileSystemBrowserService.class);
				String fsbChoice = (fsbService != null) ? "File system" : null;
				int choice = OptionDialog.showOptionDialog(parent, "Container file detected",
					"The file " + refdFile.get().file.getName() +
						" seems to have nested files in it.  Select an import mode:",
					"Single file", "Batch", fsbChoice, OptionDialog.QUESTION_MESSAGE);
				if (choice == 1) {
					importSingleFile(fqFSRL.get(), destFolder, suggestedDestinationPath, tool,
						programManager);
				}
				else if (choice == 2) {
					BatchImportDialog.showAndImport(tool, null, Arrays.asList(fqFSRL.get()),
						destFolder, programManager);
				}
				else if (choice == 3) {
					fsbService.openFileSystem(fqFSRL.get());
				}
			}
			else {
				// If file was normal,
				// do a normal single-file import
				importSingleFile(fqFSRL.get(), destFolder, suggestedDestinationPath, tool,
					programManager);
			}
		}
		finally {
			if (refdFile.get() != null) {
				try {
					refdFile.get().close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

	}

	public static void showAddToProgramDialog(FSRL fsrl, Program program, PluginTool tool,
			TaskMonitor monitor) {

		try {
			ByteProvider provider = FileSystemService.getInstance().getByteProvider(fsrl, monitor);

			if (provider.length() == 0) {
				Msg.showWarn(null, null, "Error opening " + fsrl.getName(),
					"The item does not correspond to a valid file.");
				return;
			}
			Map<Loader, Collection<LoadSpec>> loadMap =
				LoaderService.getAllSupportedLoadSpecs(provider);

			SystemUtilities.runSwingLater(() -> {
				AddToProgramDialog dialog =
					new AddToProgramDialog(tool, fsrl, loadMap, provider, program);
				tool.showDialog(dialog);
			});
		}
		catch (IOException e) {
			Msg.showError(ImporterUtilities.class, null, "Error reading data",
				"I/O error reading " + fsrl.getName(), e);
		}
		catch (CancelledException e) {
			// just return
		}

	}

	/**
	 * Constructs a {@link ImporterDialog} and shows it in the swing thread.
	 * <p>
	 *
	 * @param fsrl the file system resource locater (can be a simple file or an element of
	 * a more complex file such as a zip file)
	 * @param defaultFolder the default destination folder for the imported file. Can be null.
	 * @param suggestedDestinationPath optional string path that will automatically be pre-pended
	 * to the destination filename.
	 * @param tool the parent UI component
	 * @param programManager optional {@link ProgramManager} instance to open the imported file in.
	 * @throws IOException if there was an IO-related issue importing the file.
	 * @throws CancelledException if the import was canceled.
	 */
	private static void importSingleFile(FSRL fsrl, DomainFolder defaultFolder,
			String suggestedDestinationPath, PluginTool tool, ProgramManager programManager) {

		TaskLauncher.launchNonModal("Import File", monitor -> {
			try {
				ByteProvider provider =
					FileSystemService.getInstance().getByteProvider(fsrl, monitor);
				Map<Loader, Collection<LoadSpec>> loadMap =
					LoaderService.getAllSupportedLoadSpecs(provider);

				SystemUtilities.runSwingLater(() -> {
					ImporterDialog importerDialog = new ImporterDialog(tool, programManager,
						loadMap, provider, suggestedDestinationPath);
					if (defaultFolder != null) {
						importerDialog.setDestinationFolder(defaultFolder);
					}
					tool.showDialog(importerDialog);
				});
			}
			catch (IOException ioe) {
				Msg.showError(ImporterUtilities.class, tool.getActiveWindow(),
					"Error Importing File", "Error when importing file " + fsrl, ioe);
			}
			catch (CancelledException e) {
				Msg.info(ImporterUtilities.class, "Import single file " + fsrl + " cancelled");
			}
		});
	}

	private static void doFSImport(RefdFile refdFile, FSRL fsrl, DomainFolder destFolderParam,
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
	 * @param fsrl import file location
	 * @param destFolder project destination folder
	 * @param loadSpec import {@link LoadSpec}
	 * @param programName program name
	 * @param options import options
	 * @param tool tool to which popup dialogs should be associated
	 * @param programManager program manager to open imported file with or null
	 * @param monitor task monitor
	 */
	public static void doSingleImport(FSRL fsrl, DomainFolder destFolder, LoadSpec loadSpec,
			String programName, List<Option> options, PluginTool tool,
			ProgramManager programManager, TaskMonitor monitor) {

		// Do a normal single-file import
		try (ByteProvider bp = FileSystemService.getInstance().getByteProvider(fsrl, monitor)) {

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
				if (programManager != null) {
					int openState =
						firstProgram ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE;
					programManager.openProgram(program, openState);
				}
				ImporterUtilities.setProgramProperties(program, fsrl, monitor);
				ProgramMappingService.createAssociation(fsrl, program);
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

	public static void doAddToProgram(FSRL fsrl, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, PluginTool tool) {
		MessageLog messageLog = new MessageLog();
		try (ByteProvider bp = FileSystemService.getInstance().getByteProvider(fsrl, monitor)) {
			loadSpec.getLoader().loadInto(bp, loadSpec, options, messageLog, program, monitor,
				MemoryConflictHandler.ALWAYS_OVERWRITE);
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
