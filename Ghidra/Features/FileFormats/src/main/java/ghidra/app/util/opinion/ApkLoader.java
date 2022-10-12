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
package ghidra.app.util.opinion;

import java.io.IOException;
import java.util.*;

import org.jdom.*;
import org.jdom.input.SAXBuilder;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.recognizer.PkzipRecognizer;
import ghidra.app.util.recognizer.Recognizer;
import ghidra.file.formats.android.dex.DexHeaderFactory;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.file.formats.android.multidex.MultiDexLinker;
import ghidra.file.formats.android.versions.AndroidVersion;
import ghidra.file.formats.android.versions.AndroidVersionManager;
import ghidra.file.formats.android.xml.AndroidXmlFileSystem;
import ghidra.file.formats.zip.ZipFileSystem;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public class ApkLoader extends DexLoader {

	@Override
	public String getName() {
		return "Android APK";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		if (isZip(provider)) {
			try (ZipFileSystem zipFS = openAPK(provider, TaskMonitor.DUMMY)) {
				return findLoadSpecs(zipFS, TaskMonitor.DUMMY);
			}
			catch (Exception e) {
				//ignore
			}
		}
		return Collections.emptyList();
	}

	@Override
	protected List<LoadedProgram> loadProgram(ByteProvider provider, String programName,
			DomainFolder programFolder, LoadSpec loadSpec, List<Option> options, MessageLog log,
			Object consumer, TaskMonitor monitor) throws CancelledException, IOException {

		boolean success = false;
		List<LoadedProgram> allLoadedPrograms = new ArrayList<>();
		int dexIndex = 1;//DEX file numbering starts at 1
		try (ZipFileSystem zipFS = openAPK(provider, monitor)) {
			while (!monitor.isCancelled()) {
				GFile classesDexFile =
					zipFS.lookup("/" + "classes" + (dexIndex == 1 ? "" : dexIndex) + ".dex");

				if (classesDexFile == null) {//done
					break;
				}

				monitor.setMessage(
					"Loading " + classesDexFile.getName() + " from " + programName + "...");

				try (ByteProvider dexProvider =
					zipFS.getByteProvider(classesDexFile, monitor)) {
					// defer to the super class (DexLoader) to actually load the DEX file
					List<LoadedProgram> loadedPrograms =
						super.loadProgram(dexProvider, classesDexFile.getName(), programFolder,
							loadSpec, options, log, consumer, monitor);

					allLoadedPrograms.addAll(loadedPrograms);
				}
				++dexIndex;
			}
			success = true;
		}
		catch (IOException e) {
			log.appendException(e);
		}
		finally {
			if (!success) {
				release(allLoadedPrograms, consumer);
			}
		}
		link(allLoadedPrograms.stream().map(e -> e.program()).toList(), log, monitor);
		return allLoadedPrograms;
	}

	@Override
	protected boolean isOverrideMainProgramName() {
		//preserve the classesX.dex file names...
		return false;
	}

	/**
	 * Quickly check if the provider is a ZIP file.
	 * @param provider the byte provider
	 * @return TRUE if a valid ZIP file.
	 */
	private boolean isZip(ByteProvider provider) {
		try {
			Recognizer recog = new PkzipRecognizer();
			byte[] bytes = provider.readBytes(0, recog.numberOfBytesRequired());
			return recog.recognize(bytes) != null;
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

	/**
	 * Inspects the APK to locate the manifest and classes.dex files.
	 * If found use the manifest to determine the Android version. 
	 * @param zipFS the ZIP file system of the APK file
	 * @return collection of load specs
	 * @throws IOException if exception occurs reading the ZIP file.
	 */
	private Collection<LoadSpec> findLoadSpecs(ZipFileSystem zipFS, TaskMonitor monitor)
			throws IOException {

		GFile manifestXmlFile = zipFS.lookup("/" + "AndroidManifest.xml");
		GFile classesDexFile = zipFS.lookup("/" + "classes.dex");

		if (manifestXmlFile != null) {
			List<LoadSpec> xmlSpecs = processManifest(zipFS, manifestXmlFile, monitor);
			if (!xmlSpecs.isEmpty()) {
				//make sure APK contains classes.dex, some are empty
				if (classesDexFile != null) {
					return xmlSpecs;
				}
			}
		}

		//should NOT be else/if
		if (classesDexFile != null) {
			return processDEX(zipFS, classesDexFile, monitor);
		}

		return Collections.emptyList();
	}

	/**
	 * Reads the Android manifest file and returns the
	 * Android OS version string. For example, "N" or "S".
	 * Use this string to select the appropriate Sleigh module
	 * in the importer.
	 * @param zipFS the ZIP file system of the APK file
	 * @param manifestFile the manifest file from the ZIP
	 * @param monitor the task monitor
	 * @return Android OS version string. For example, "N" or "S".
	 * @throws IOException if exception occurs reading the manifest file. 
	 */
	private List<LoadSpec> processManifest(ZipFileSystem zipFS, GFile manifestFile,
			TaskMonitor monitor)
			throws IOException {

		List<LoadSpec> loadSpecs = new ArrayList<>();
		monitor.setMessage("Reading Android Manifest ...");
		try {
			ByteProvider byteProvider =
				zipFS.getByteProvider(manifestFile, monitor);

			try (AndroidXmlFileSystem xmlFS =
				openManifest(manifestFile.getName(), byteProvider, monitor)) {

				GFile xmlFile = xmlFS.getPayloadFile();
				ByteProvider xmlFileByteProvider = xmlFS.getByteProvider(xmlFile, monitor);

				SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
				Document document = sax.build(xmlFileByteProvider.getInputStream(0));
				Element rootElement = document.getRootElement();
				AndroidVersion version = getAndroidVersion(rootElement);

				List<QueryResult> queries =
					QueryOpinionService.query(getName(), DexConstants.MACHINE,
						String.valueOf(version.getVersionLetter()));

				for (QueryResult result : queries) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
			}
		}
		catch (Exception e) {
			//ignore
		}
		return loadSpecs;
	}

	private AndroidVersion getAndroidVersion(Element rootElement) {
		Attribute codeAttribute =
			rootElement.getAttribute(AndroidVersionManager.PLATFORM_BUILD_VERSION_CODE);
		String platformBuildVersionCode = codeAttribute == null ? null : codeAttribute.getValue();
		Attribute nameAttribute =
			rootElement.getAttribute(AndroidVersionManager.PLATFORM_BUILD_VERSION_NAME);
		String platformBuildVersionName = nameAttribute == null ? null : nameAttribute.getValue();
		return AndroidVersionManager.getByPlatformBuildVersion(platformBuildVersionCode,
			platformBuildVersionName);
	}

	/**
	 * Loads the "classes.dex" file to determine the LoadSpec
	 * @param zipFS the Android APK file system
	 * @param file the classes.dex file from the file system
	 * @param monitor the task monitor
	 * @return the list of LoadSpec, could be empty list
	 * @throws IOException if exception occurs reading the classes.dex file. 
	 */
	private List<LoadSpec> processDEX(ZipFileSystem zipFS, GFile file, TaskMonitor monitor)
			throws IOException {

		monitor.setMessage("Reading classes.dex ...");
		List<LoadSpec> loadSpecs = new ArrayList<>();
		try {
			ByteProvider byteProvider =
				zipFS.getByteProvider(file, monitor);
			BinaryReader reader = new BinaryReader(byteProvider, true);
			DexHeader header = DexHeaderFactory.getDexHeader(reader);
			if (DexConstants.DEX_MAGIC_BASE.equals(new String(header.getMagic()))) {
				List<QueryResult> queries =
					QueryOpinionService.query(getName(), DexConstants.MACHINE, null);
				for (QueryResult result : queries) {
					loadSpecs.add(new LoadSpec(this, 0, result));
				}
				if (loadSpecs.isEmpty()) {
					loadSpecs.add(new LoadSpec(this, 0, true));
				}
			}
		}
		catch (CancelledException e) {
			//ignore
		}
		return loadSpecs;
	}

	/**
	 * Opens the Android APK as a ZIP file system.
	 * @param provider the byte provider
	 * @param monitor the task monitor
	 * @return the ZipFileSystem
	 */
	private ZipFileSystem openAPK(ByteProvider provider, TaskMonitor monitor)
			throws IOException, CancelledException {

		FileSystemService fsService = FileSystemService.getInstance();
		return fsService.mountSpecificFileSystem(provider.getFSRL(), ZipFileSystem.class, monitor);
	}

	/**
	 * Opens the Android manifest XML file system.
	 * @param name the name of the file
	 * @param provider the byte provider
	 * @param monitor the task monitor
	 * @return the AndroidXmlFileSystem
	 */
	private AndroidXmlFileSystem openManifest(String name, ByteProvider provider,
			TaskMonitor monitor) {

		AndroidXmlFileSystem xmlFS = new AndroidXmlFileSystem(name, provider);
		xmlFS.setFilesystemService(FileSystemService.getInstance());
		xmlFS.setFSRL(provider.getFSRL().getFS());
		try {
			xmlFS.open(monitor);
		}
		catch (CancelledException | IOException e) {
			//ignore
		}
		return xmlFS;
	}

	/**
	 * Links the DEX programs together.
	 * @param programList the list of DEX files loaded as programs
	 * @param log the message log
	 * @param monitor the task monitor
	 */
	private void link(List<Program> programList, MessageLog log, TaskMonitor monitor) {
		MultiDexLinker linker = new MultiDexLinker(programList);
		try {
			linker.link(monitor);
			linker.clear(monitor);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}
}
