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
package pdb;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Properties;

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.context.ProgramContextAction;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.pdb.PdbException;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.bin.format.pdb.PdbParser.PdbFileType;
import ghidra.app.util.pdb.PdbLocator;
import ghidra.app.util.pdb.PdbProgramAttributes;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorRestrictions;
import ghidra.framework.Application;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.net.http.HttpUtil;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

/**
 * Plugin that allows users to download PDB files from a Symbol Server URL.
 *
 * PDB files can be of type .pdb, .pdb.xml, and .cab:
 * 		- .pdb files are Microsoft's native representation of debug symbols
 * 		- .pdb.xml files are representations of .pdb files using XML. Ghidra provides a script
 * 		  for users to transform .pdb files into .pdb.xml files.
 * 		- .cab (cabinet) files are compressed .pdb files. A Symbol Server set up using Microsoft
 * 		  tools will allow download of .cab files, relying on the user to extract a .pdb from
 *        the .cab file.
 *
 * The Symbol Server can be a URL to a hosted file system or a server that was set up using Microsoft
 * tools. This code will also take care of PKI authentication, if needed by the server.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Download PDB Files from a Symbol Server",
	description = "This plugin manages the downloading of PDB files from a Symbol Server."
)
//@formatter:on
public class PdbSymbolServerPlugin extends Plugin {

	private static final String symbolServerEnvVar = "_NT_SYMBOL_PATH";

	private static final String PDB_URL_PROPERTY = "PDB Symbol Server";

	private static String expectedPdbContentType = "application/octet-stream";
	private static String expectedXmlContentType = "text/xml";
	private static Properties urlProperties = null;

	// Store last-selected value(s) for askXxx methods
	private static String serverUrl = null;
	private static File localDir = null;
	private PdbFileType fileType = PdbFileType.PDB;
	private boolean includePePdbPath = false;

	enum RetrieveFileType {
		PDB, XML, CAB
	}

	enum ReturnPdbStatus {
		DOWNLOADED, EXISTING, NOT_FOUND;
	}

	public PdbSymbolServerPlugin(PluginTool tool) {
		super(tool);
		createActions();

		urlProperties = new Properties();
		// Version # appears to be debugger version. 6.3.9600.17298
		urlProperties.setProperty("User-Agent", "Microsoft-Symbol-Server/6.3.9600.17298");
	}

	/**
	 * Sets the {@link PdbFileType}
	 * @param fileType the {@link PdbFileType}
	 */
	public void setPdbFileType(PdbFileType fileType) {
		this.fileType = fileType;
	}

	private void createActions() {
		ProgramContextAction downloadPdbAction =
			new ProgramContextAction("Download_PDB_File", this.getName()) {

				@Override
				public boolean isEnabledForContext(ProgramActionContext context) {
					return context.getProgram() != null;
				}

				@Override
				protected void actionPerformed(ProgramActionContext programContext) {
					downloadPDB();
				}
			};

		MenuData menuData =
			new MenuData(new String[] { "&File", "Download PDB File..." }, null, "Import PDB");
		menuData.setMenuSubGroup("4");
		downloadPdbAction.setMenuBarData(menuData);

		downloadPdbAction.setEnabled(false);
		downloadPdbAction.setHelpLocation(new HelpLocation("Pdb", downloadPdbAction.getName()));
		tool.addAction(downloadPdbAction);
	}

	private void downloadPDB() {
		Program program = GhidraProgramUtilities.getCurrentProgram(tool);

		try {

			PdbFileAndStatus returnPdb = getPdbFile(program);

			File returnedPdbFile = returnPdb.getPdbFile();

			switch (returnPdb.getPdbStatus()) {
				case NOT_FOUND:
					Msg.showInfo(getClass(), null, "Error", "Could not download the " + fileType +
						" file for this version of " + program.getName() + " from " + serverUrl);
					break;

				case DOWNLOADED:
					Msg.showInfo(getClass(), null, "File Retrieved", "Downloaded and saved file '" +
						returnedPdbFile.getName() + "' to \n" + returnedPdbFile.getParent());
					// no break here, since we want it to continue

				case EXISTING:
					tryToLoadPdb(returnedPdbFile, program);
					break;
			}
		}
		catch (CancelledException ce) {
			tool.setStatusInfo("Downloading PDB from Symbol Server was cancelled.");
			return;
		}
		catch (PdbException pe) {
			Msg.showInfo(getClass(), null, "Error", "Error: " + pe.getMessage());
		}
		catch (IOException ioe) {
			Msg.showInfo(getClass(), null, "Error",
				ioe.getClass().getSimpleName() + ": " + ioe.getMessage());

			// If URL connection failed, then reset the dialog to show the default symbol server
			// (instead of the last one we attempted to connect to).
			if (ioe instanceof UnknownHostException) {
				serverUrl = null;
			}
		}
	}

	/**
	 * Retrieves PDB, using GUI to interact with user to get PDB and Symbol Server Information
	 *
	 * @param program  program for which to retrieve the PDB file
	 * @return  the retrieved PDB file (could be in .pdb or .xml form)
	 * @throws CancelledException upon user cancellation
	 * @throws IOException if an I/O issue occurred
	 * @throws PdbException if there was a problem with the PDB attributes
	 */
	private PdbFileAndStatus getPdbFile(Program program)
			throws CancelledException, IOException, PdbException {

		try {
			PdbProgramAttributes pdbAttributes = PdbParser.getPdbAttributes(program);

			if (pdbAttributes.getGuidAgeCombo() == null) {
				throw new PdbException(
					"Incomplete PDB information (GUID/Signature and/or age) associated with this program.\n" +
						"Either the program is not a PE, or it was not compiled with debug information.");
			}

			// 1. Ask if user wants .pdb or .pdb.xml file
			fileType = askForFileExtension();

			// 1.5 Ask if should search PE-specified PDB path.
			includePePdbPath = askIncludePeHeaderPdbPath();

			String symbolEnv = System.getenv(symbolServerEnvVar);
			if (symbolEnv != null) {
				parseSymbolEnv(symbolEnv);
			}

			// 2. Ask for local storage location
			localDir = askForLocalStorageLocation();

			// 3. See if PDB can be found locally
			File pdbFile = PdbParser.findPDB(pdbAttributes, includePePdbPath, localDir, fileType);

			// 4. If not found locally, ask if it should be retrieved
			if (pdbFile != null && pdbFile.getName().endsWith(fileType.toString())) {

				String htmlString =
					HTMLUtilities.toWrappedHTML("Found potential* matching PDB at: \n   " +
						pdbFile.getAbsolutePath() + "\n\n* Match determined by file name only; " +
						"not vetted for matching GUID/version." +
						"\n\nContinue with download?\n\n" +
						"<i>(downloaded file will be saved in a directory of the form " +
						localDir.getAbsolutePath() + File.separator + "&lt;pdbFilename&gt;" +
						File.separator + "&lt;GUID&gt;" + File.separator + ")</i>");

				// Warn that there is already a matching file
				int response =
					OptionDialog.showYesNoDialog(null, "Potential Matching PDB Found", htmlString);

				switch (response) {
					case 0:
						// User cancelled
						throw new CancelledException();

					case 1:
						// Yes -- do nothing here
						break;

					case 2:
						// No
						return new PdbFileAndStatus(pdbFile, ReturnPdbStatus.EXISTING);

					default:
						// do nothing
				}
			}

			// 5. Ask for Symbol Server location
			serverUrl = askForSymbolServerUrl();

			// Fix up URL
			if (!serverUrl.endsWith("/")) {
				serverUrl += "/";
			}

			File downloadedPdb = attemptToDownloadPdb(pdbAttributes, serverUrl, localDir);

			if (downloadedPdb != null) {
				return new PdbFileAndStatus(downloadedPdb, ReturnPdbStatus.DOWNLOADED);
			}

			return new PdbFileAndStatus();
		}
		finally {
			// Store the dialog choices
			Preferences.store();
		}
	}

	private void parseSymbolEnv(String envString) {

		// Expect the environment string to be of the form:
		//    srv*[local cache]*[private symbol server]*https://msdl.microsoft.com/download/symbols
		//    srv*c:\symbols*https://msdl.microsoft.com/download/symbols

		if (!envString.startsWith("srv") && !envString.startsWith("SRV")) {
			return;
		}

		String[] envParts = envString.split("\\*");

		if (envParts.length < 3) {
			return;
		}

		File storageDir = new File(envParts[1]);
		if (storageDir.isDirectory()) {
			localDir = storageDir;
		}

		serverUrl = envParts[2];

		Msg.info(getClass(), "Using server URL: " + serverUrl);
	}

	private PdbFileType askForFileExtension() throws CancelledException {
		//@formatter:off
		int choice = OptionDialog.showOptionDialog(
			null,
			"pdb or pdb.xml",
			"Download a .pdb or .pdb.xml file?",
			"PDB",
			"XML");
		//@formatter:on

		if (choice == OptionDialog.CANCEL_OPTION) {
			throw new CancelledException();
		}
		return (choice == OptionDialog.OPTION_ONE) ? PdbFileType.PDB : PdbFileType.XML;
	}

	private boolean askIncludePeHeaderPdbPath() throws CancelledException {
		//@formatter:off
		int choice = OptionDialog.showOptionDialog(
			null,
			"PE-specified PDB Path",
			"Unsafe: Include PE-specified PDB Path in search for existing PDB",
			"Yes",
			"No");
		//@formatter:on

		if (choice == OptionDialog.CANCEL_OPTION) {
			throw new CancelledException();
		}
		return (choice == OptionDialog.OPTION_ONE);
	}

	String askForSymbolServerUrl() throws CancelledException {

		AskPdbUrlDialog dialog;
		String dialogResponse = null;
		String storedURL;

		if (serverUrl != null) {
			storedURL = serverUrl;
		}
		else {
			storedURL = Preferences.getProperty(PDB_URL_PROPERTY);

			if (storedURL == null) {
				storedURL = "";
			}
		}

		while (dialogResponse == null) {
			dialog = new AskPdbUrlDialog("Symbol Server URL", "What is the Symbol Server URL?",
				storedURL);

			if (dialog.isCanceled()) {
				throw new CancelledException();
			}

			dialogResponse = dialog.getValueAsString();

			// Make sure user has included either 'http' or 'https'
			if (!dialogResponse.startsWith("http")) {
				Msg.showInfo(getClass(), null, "Incomplete URL",
					"URL should start with either 'http' or 'https'.");
				dialogResponse = null;
				continue;
			}

			// Make sure that URL has valid syntax
			try {
				new URL(dialogResponse);
			}
			catch (MalformedURLException malExc) {
				Msg.showInfo(getClass(), null, "Malformed URL", malExc.toString());
				dialogResponse = null;
			}
		}

		Preferences.setProperty(PDB_URL_PROPERTY, dialogResponse);

		return dialogResponse;
	}

	private File askForLocalStorageLocation() throws CancelledException {

		final GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getActiveWindow());

		// Need to store the variable in an array to allow the final variable to be reassigned.
		// Using an array prevents the compiler from warning about "The final local variable
		// cannot be assigned, since it is defined in an enclosing type."
		final File[] chosenDir = new File[1];

		File testDirectory = null;

		// localDir is not null if we already parsed the _NT_SYMBOL_PATH environment var
		if (localDir != null) {
			testDirectory = localDir;
		}
		else {
			testDirectory = PdbLocator.getDefaultPdbSymbolsDir();
		}

		final File storedDirectory = testDirectory;

		Runnable r = () -> {
			while (chosenDir[0] == null && !fileChooser.wasCancelled()) {
				fileChooser.setSelectedFile(storedDirectory);

				fileChooser.setTitle("Select Location to Save Retrieved File");
				fileChooser.setApproveButtonText("OK");
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
				chosenDir[0] = fileChooser.getSelectedFile();

				if (chosenDir[0] != null) {
					if (!chosenDir[0].exists()) {
						Msg.showInfo(getClass(), null, "Directory does not exist",
							"The directory '" + chosenDir[0].getAbsolutePath() +
								"' does not exist. Please create it or choose a valid directory.");
						chosenDir[0] = null;
					}
					else if (chosenDir[0].isFile()) {
						Msg.showInfo(getClass(), null, "Invalid Directory",
							"The location '" + chosenDir[0].getAbsolutePath() +
								"' represents a file, not a directory. Please choose a directory.");
						chosenDir[0] = null;
					}
				}
			}
		};
		SystemUtilities.runSwingNow(r);

		if (fileChooser.wasCancelled()) {
			throw new CancelledException();
		}

		PdbLocator.setDefaultPdbSymbolsDir(chosenDir[0]);

		return chosenDir[0];
	}

	/**
	 * Attempt to download a file from a URL and save it to the specified location.
	 *
	 * @param fileUrl  URL from which to download the file
	 * @param fileDestination  location at which to save the downloaded file
	 * @return  whether download/save succeeded
	 * @throws IOException if an I/O issue occurred
	 * @throws PdbException if issue with PKI certificate
	 */
	boolean retrieveFile(String fileUrl, File fileDestination) throws IOException, PdbException {
		return retrieveFile(fileUrl, fileDestination, null);
	}

	/**
	 * Attempt to download a file from a URL and save it to the specified location.
	 *
	 * @param fileUrl  URL from which to download the file
	 * @param fileDestination  location at which to save the downloaded file
	 * @param retrieveProperties  optional HTTP request header values to be included (may be null)
	 * @return whether download/save succeeded
	 * @throws IOException if an I/O issue occurred
	 * @throws PdbException if issue with PKI certificate
	 */
	boolean retrieveFile(String fileUrl, File fileDestination, Properties retrieveProperties)
			throws IOException, PdbException {

		String expectedContentType =
			(fileType == PdbFileType.PDB) ? expectedPdbContentType : expectedXmlContentType;

		try {
			String contentType =
				HttpUtil.getFile(fileUrl, retrieveProperties, true, fileDestination);

			if (contentType != null && !contentType.equals(expectedContentType)) {
				fileDestination.delete();
				return false;
			}
		}
		catch (IOException ioe) {

			// No PKI Certificate installed
			if (ioe.getMessage().equals("Forbidden")) {
				throw new PdbException(
					"PKI Certificate needed for user authentication.\nTo set a " +
						"certificate, use the Project Window's 'Edit -> Set PKI Certificate' Action.");
			}

			if (!ioe.getMessage().equals("Not Found")) {
				throw ioe;
			}
		}

		return fileDestination.exists();

	}

	/**
	 * Take given file and move it to the specified destination folder in the location
	 * &lt;destination folder&gt;/&lt;pdbFilename&gt;/&gt;guidAgeString&lt; (subfolders that do not
	 * already exist will be created).
	 *
	 * @param destinationFolder  root folder to which the given file will be moved
	 * @param pdbFilename  name of PDB file (subfolder with this name will be created under destination
	 *            folder, if it doesn't already exist)
	 * @param guidAgeString  guidAge string of the PDB (subfolder with this name will be created under
	 *            &lt;destination folder&gt;/&lt;pdbFilename&gt; folder, if it doesn't already exist)
	 * @param downloadFilename  name of final moved file (can be same as pdbFilename)
	 * @param tempFile  actual file to be moved
	 * @return  file that was moved (and optionally renamed) in its new location
	 * @throws IOException if there was an IO-related problem making the directory or moving the file
	 */
	File createSubFoldersAndMoveFile(File destinationFolder, String pdbFilename,
			String guidAgeString, String downloadFilename, File tempFile) throws IOException {

		File pdbOuterSaveDir = makeDirectory(destinationFolder, pdbFilename);
		File pdbInnerSaveDir = makeDirectory(pdbOuterSaveDir, guidAgeString);

		File finalDestFile = new File(pdbInnerSaveDir, downloadFilename);

		try {
			Files.move(tempFile.toPath(), finalDestFile.toPath(),
				StandardCopyOption.REPLACE_EXISTING);
		}
		catch (IOException e) {
			tempFile.delete();
			throw new IOException("Could not save file: " + finalDestFile.getAbsolutePath());
		}

		return finalDestFile;
	}

	private File makeDirectory(File parentFolder, String directoryName) throws IOException {
		File newDir = new File(parentFolder, directoryName);

		if (newDir.isFile()) {
			throw new IOException("Trying to create folder " + newDir.getAbsolutePath() +
				",\nbut it shares the same name as an existing file.\n" +
				"Please try downloading PDB again, selecting a " +
				"non-conflicting destination folder.");
		}

		if (!newDir.isDirectory()) {
			boolean madeDir = newDir.mkdir();
			if (!madeDir) {
				throw new IOException(
					"Trying to create parent folders to store PDB file. Could not create directory " +
						newDir.getAbsolutePath() + ".");
			}
		}

		return newDir;
	}

	/**
	 * Expand cabinet (.cab) files (Windows compressed format).
	 *
	 * When on Windows, use the 'expand' command (should already be included with the OS).
	 * When on Unix/Mac, use 'cabextract', which has been included with Ghidra.
	 *
	 * @param cabFile  file to expand/uncompress
	 * @param targetFilename  file to save uncompressed *.pdb to
	 * @return  the file that was uncompressed
	 * @throws PdbException if failure with cabinet extraction
	 * @throws IOException if issue starting the {@link ProcessBuilder}
	 */
	File uncompressCabFile(File cabFile, String targetFilename) throws PdbException, IOException {

		String cabextractPath = null;
		String[] cabextractCmdLine;

		if (PdbParser.onWindows) {
			File cabextractExe = new File("C:\\Windows\\System32\\expand.exe");

			if (!cabextractExe.exists()) {
				throw new PdbException(
					"Expected to find cabinet expansion utility 'expand.exe' in " +
						cabextractExe.getParent());
			}

			cabextractPath = cabextractExe.getAbsolutePath();

			// expand -R <source>.cab -F:<files> <destination>
			// -R renames from .cab to .pdb
			// -F specifies which files within cab to expand
			cabextractCmdLine = new String[] { cabextractPath, "-R", cabFile.getAbsolutePath(),
				"-F:" + targetFilename, cabFile.getParent() };
		}
		else {

			// On Mac/Linux
			try {
				cabextractPath = Application.getOSFile("cabextract").getAbsolutePath();
			}
			catch (FileNotFoundException e) {
				throw new PdbException("Unable to find 'cabextract' executable.");
			}

			// -q for quiet
			// -d to specify where to extract to
			// -F to specify filter pattern of file(s) to extract
			cabextractCmdLine = new String[] { cabextractPath, "-q", "-d", cabFile.getParent(),
				"-F", targetFilename, cabFile.getAbsolutePath() };
		}

		ProcessBuilder builder = new ProcessBuilder(cabextractCmdLine);
		Process currentProcess = builder.start();

		try {
			int exitValue = currentProcess.waitFor();

			if (exitValue != 0) {
				throw new PdbException("Abnormal termination of 'cabextract' process.");
			}
		}
		catch (InterruptedException ie) {
			// do nothing
		}

		// Look for the file
		FilenameFilter pdbFilter = (dir, filename) -> {
			String lowercaseName = filename.toLowerCase();
			return (lowercaseName.endsWith(fileType.toString()));
		};

		File[] files = cabFile.getParentFile().listFiles(pdbFilter);
		if (files != null) {
			for (File childFile : files) {
				if (childFile.getName().equals(targetFilename)) {
					return childFile;
				}
			}
		}

		return null;
	}

	/**
	 * Download a file, then move it to its final destination. URL for download is created by
	 * combining downloadURL and PDB file attributes. Final move destination is also determined
	 * by the PDB file attributes.
	 *
	 * @param pdbAttributes PDB attributes (GUID, age, potential PDB locations, etc.)
	 * @param downloadUrl Root URL to search for the PDB
	 * @param saveToLocation Final root directory to save the file
	 * @return the downloaded and moved file
	 * @throws IOException if an I/O issue occurred
	 * @throws PdbException if issue with PKI certificate or cabinet extraction
	 */
	private File attemptToDownloadPdb(PdbProgramAttributes pdbAttributes, String downloadUrl,
			File saveToLocation) throws PdbException, IOException {

		// Get location of the user's 'temp' directory
		String tempDirPath = System.getProperty("java.io.tmpdir");
		File tempDir = new File(tempDirPath);

		RetrieveFileType retrieveType =
			(fileType == PdbFileType.XML) ? RetrieveFileType.XML : RetrieveFileType.PDB;

		// Attempt retrieval from connection (encrypted or non-encrypted are handled) by HttpUtil
		File createdFile = downloadExtractAndMoveFile(pdbAttributes, downloadUrl, tempDir,
			saveToLocation, retrieveType);

		if (createdFile != null) {
			return createdFile;
		}

		// If Microsoft-specific server, need to do more (i.e., filename will be named *.pd_ and in
		// .cab format). Need to change http connection properties to be able to pull back file.

		// Attempt retrieval as if it was a Microsoft-specific URL
		if (retrieveType == RetrieveFileType.PDB) {
			return downloadExtractAndMoveFile(pdbAttributes, downloadUrl, tempDir, saveToLocation,
				RetrieveFileType.CAB);
		}

		return null;
	}

	/**
	 * Download a file, then move it to its final destination. URL for download is created by
	 * combining downloadURL and PDB file attributes. Final move destination is also determined
	 * by the PDB file attributes.
	 *
	 * @param pdbAttributes  PDB attributes (GUID, age, potential PDB locations, etc.)
	 * @param downloadUrl  Root URL to search for the PDB
	 * @param tempSaveDirectory  Temporary local directory to save downloaded file (which will be moved)
	 * @param finalSaveDirectory  Final root directory to save the file
	 * @param retrieveFileType the {@link RetrieveFileType}
	 * @return the downloaded and moved file
	 * @throws IOException if an I/O issue occurred
	 * @throws PdbException if issue with PKI certificate or cabinet extraction
	 */
	File downloadExtractAndMoveFile(PdbProgramAttributes pdbAttributes, String downloadUrl,
			File tempSaveDirectory, File finalSaveDirectory, RetrieveFileType retrieveFileType)
			throws IOException, PdbException {

		// TODO: This should be performed by a monitored Task with ability to cancel

		String guidAgeString = pdbAttributes.getGuidAgeCombo();
		List<String> potentialPdbFilenames = pdbAttributes.getPotentialPdbFilenames();
		File tempFile = null;
		String tempFileExtension = (retrieveFileType == RetrieveFileType.CAB) ? "cab" : "pdb";

		File returnFile = null;

		try {

			tempFile = new File(tempSaveDirectory, "TempPDB." + tempFileExtension);

			// Attempt retrieval from connection (encrypted or non-encrypted are handled)
			for (String pdbFilename : potentialPdbFilenames) {

				String downloadFilename = pdbFilename;
				String currentUrl = downloadUrl + pdbFilename + "/" + guidAgeString + "/";

				boolean retrieveSuccess = false;

				switch (retrieveFileType) {
					case CAB:
						currentUrl += downloadFilename;
						currentUrl = currentUrl.substring(0, currentUrl.length() - 1) + "_";
						retrieveSuccess = retrieveFile(currentUrl, tempFile, urlProperties);

						if (!retrieveSuccess) {
							continue;
						}

						File extractedFile = uncompressCabFile(tempFile, pdbFilename);

						if (extractedFile == null) {
							throw new IOException(
								"Unable to uncompress .cab file extracted for " + pdbFilename);
						}
						returnFile = extractedFile;

						break;

					case PDB:
						currentUrl += downloadFilename;
						retrieveSuccess = retrieveFile(currentUrl, tempFile);

						if (!retrieveSuccess) {
							continue;
						}

						returnFile = tempFile;
						break;

					case XML:
						downloadFilename += ".xml";
						currentUrl += downloadFilename;
						retrieveSuccess = retrieveFile(currentUrl, tempFile);

						if (!retrieveSuccess) {
							continue;
						}

						returnFile = tempFile;
						break;
				}

				return createSubFoldersAndMoveFile(finalSaveDirectory, pdbFilename, guidAgeString,
					downloadFilename, returnFile);

			}
		}
		finally {
			if (tempFile != null && tempFile.exists()) {
				tempFile.delete();
			}
		}
		return null;
	}

	private void tryToLoadPdb(File downloadedPdb, Program currentProgram) {

		AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(currentProgram);
		if (aam.isAnalyzing()) {
			Msg.showWarn(getClass(), null, "Load PDB",
				"Unable to load PDB file while analysis is running.");
			return;
		}

		boolean analyzed =
			currentProgram.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false);

		String message = "Would you like to apply the following PDB:\n\n" +
			downloadedPdb.getAbsolutePath() + "\n\n to " + currentProgram.getName() + "?";
		if (analyzed) {
			message += "\n \nWARNING: Loading PDB after analysis has been performed may produce" +
				"\npoor results.  PDBs should generally be loaded prior to analysis or" +
				"\nautomatically during auto-analysis.";
		}

		String htmlString = HTMLUtilities.toWrappedHTML(message);
		int response = OptionDialog.showYesNoDialog(null, "Load PDB?", htmlString);
		if (response != OptionDialog.YES_OPTION) {
			return;
		}

		AskPdbOptionsDialog optionsDialog =
			new AskPdbOptionsDialog(null, fileType == PdbFileType.PDB);
		if (optionsDialog.isCanceled()) {
			return;
		}

		boolean useMsDiaParser = optionsDialog.useMsDiaParser();
		PdbApplicatorRestrictions restrictions = optionsDialog.getApplicatorRestrictions();

		tool.setStatusInfo("");

		try {
			DataTypeManagerService service = tool.getService(DataTypeManagerService.class);
			if (service == null) {
				Msg.showWarn(getClass(), null, "Load PDB",
					"Unable to locate DataTypeService in the current tool.");
				return;
			}

			TaskLauncher
				.launch(
						new LoadPdbTask(currentProgram, downloadedPdb, useMsDiaParser, restrictions,
						service));
		}
		catch (Exception pe) {
			Msg.showError(getClass(), null, "Error", pe.getMessage());
		}
	}

	class PdbFileAndStatus {

		private File pdbFile;
		private ReturnPdbStatus pdbStatus;

		public PdbFileAndStatus() {
			pdbFile = null;
			pdbStatus = ReturnPdbStatus.NOT_FOUND;
		}

		public PdbFileAndStatus(File pdbFile, ReturnPdbStatus pdbStatus) {
			this.pdbFile = pdbFile;
			this.pdbStatus = pdbStatus;
		}

		public File getPdbFile() {
			return pdbFile;
		}

		public ReturnPdbStatus getPdbStatus() {
			return pdbStatus;
		}
	}
}
