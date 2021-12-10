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
package ghidra.file.eclipse;

import java.io.*;
import java.util.List;

import org.jdom.*;

import generic.jar.ResourceFile;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.DexToJarFileSystem;
import ghidra.file.formats.android.xml.AndroidXmlFileSystem;
import ghidra.file.formats.zip.ZipFileSystem;
import ghidra.file.jad.*;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import utilities.util.FileUtilities;

/**
 * Creates an Eclipse project folder and contents based on the contents of an Android
 * APK file.
 */
public class AndroidProjectCreator {

	public static ResourceFile androidDirectory;

	static {
		ResourceFile directory = null;
		try {
			directory = Application.getModuleDataSubDirectory("android");
		}
		catch (IOException e) {
			Msg.error(AndroidProjectCreator.class, "cannot find android directory");
		}
		androidDirectory = directory;
	}

	private FSRL apkFileFSRL;
	private File eclipseProjectDirectory;
	private File srcDirectory;
	private File genDirectory;
	private File assetDirectory;

	private ResourceFile projectTemplateFile =
		new ResourceFile(androidDirectory, "eclipse-project");
	private ResourceFile classpathTemplateFile =
		new ResourceFile(androidDirectory, "eclipse-classpath");

	private MessageLog log = new MessageLog();
	private FileSystemService fsService = FileSystemService.getInstance();

	public AndroidProjectCreator(FSRL apkFileFSRL, File eclipseProjectDirectory) {
		this.apkFileFSRL = apkFileFSRL;
		this.eclipseProjectDirectory = eclipseProjectDirectory;
	}

	public void create(TaskMonitor monitor) throws IOException, CancelledException {
		createEclipseProjectDirectories();

		try (ZipFileSystem fs =
			fsService.mountSpecificFileSystem(apkFileFSRL, ZipFileSystem.class, monitor)) {
			List<GFile> listing = fs.getListing(null);
			processListing(eclipseProjectDirectory, fs, listing, monitor);
		}

		File destProjectFile =
			copyFile(projectTemplateFile, eclipseProjectDirectory, ".project", monitor);
		copyFile(classpathTemplateFile, eclipseProjectDirectory, ".classpath", monitor);

		fixupProjectFile(destProjectFile);
	}

	public MessageLog getLog() {
		return log;
	}

	private void fixupProjectFile(File projectFile) throws IOException {
		try {
			Document projectDoc = XmlUtilities.readDocFromFile(projectFile);
			Element nameElement = projectDoc.getRootElement().getChild("name");
			if (nameElement != null) {
				nameElement.setText(apkFileFSRL.getName());
				XmlUtilities.writeDocToFile(projectDoc, projectFile);
			}
		}
		catch (JDOMException e) {
			throw new IOException("Error when processing xml", e);
		}
	}

	private void createEclipseProjectDirectories() throws IOException {
		FileUtilities.checkedMkdirs(eclipseProjectDirectory);
		srcDirectory = FileUtilities.checkedMkdir(new File(eclipseProjectDirectory, "src"));
		genDirectory = FileUtilities.checkedMkdirs(new File(eclipseProjectDirectory, "gen"));
		assetDirectory = FileUtilities.checkedMkdirs(new File(eclipseProjectDirectory, "asset"));
	}

	private void processListing(File outputDirectory, GFileSystem fs, List<GFile> listing,
			TaskMonitor monitor)
			throws IOException, CancelledException {
		for (GFile child : listing) {

			String childName = child.getName();

			if (monitor.isCancelled()) {
				break;
			}
			monitor.setIndeterminate(true);

			if (child.isDirectory()) {
				if (childName.equals("META-INF")) {
					continue;
				}
				File subDir = new File(outputDirectory, childName);
				FileUtilities.checkedMkdir(subDir);
				processListing(subDir, fs, child.getListing(), monitor);
				continue;
			}

			try (ByteProvider childBP = fs.getByteProvider(child, monitor)) {
				if (childName.endsWith(".xml") &&
					AndroidXmlFileSystem.isAndroidXmlFile(childBP, monitor)) {
					processXML(outputDirectory, child, monitor);
				}
				else if (childName.endsWith("classes.dex")) {
					processDex(outputDirectory, child, monitor);
				}
				else if (childName.endsWith("resources.arsc")) {
					//TODO convert resources file back into actual resources
					copyStream(childBP, outputDirectory, child.getName(), monitor);
				}
				else if (childName.endsWith(".class")) {
					processClass(outputDirectory, child, monitor);
				}
				else {
					copyStream(childBP, outputDirectory, childName, monitor);
				}
			}
			catch (Exception e) {
				log.appendMsg("Unable to export child file: " + child.getFSRL());
				log.appendMsg("\tISSUE WAS: " + e.getMessage());
				Msg.error(this, "Unable to export child file", e);
			}
		}
	}

	private void processDex(File outputDirectory, GFile dexFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		try (DexToJarFileSystem fs = fsService.mountSpecificFileSystem(dexFile.getFSRL(),
			DexToJarFileSystem.class, monitor)) {
			GFile jarFile = fs.getJarFile();
			processJar(srcDirectory, jarFile.getFSRL(), monitor);
		}
	}

	private void processJar(File outputDirectory, FSRL jarFile, TaskMonitor monitor)
			throws IOException, CancelledException {

		JarDecompiler decompiler = new JarDecompiler(jarFile, outputDirectory);
		decompiler.decompile(monitor);

		if (decompiler.getLog().hasMessages()) {
			log.copyFrom(decompiler.getLog());
		}
	}

	private void processClass(File outputDirectory, GFile classGFile, TaskMonitor monitor)
			throws IOException, CancelledException {

		String classFileName = classGFile.getName();
		File destClassFile = new File(outputDirectory, classFileName);
		//File destJavaFile = new File(outputDirectory, PathUtils.stripExt(classFileName) + ".java");

		InputStream is = classGFile.getFilesystem().getInputStream(classGFile, monitor);
		copyStream(is, outputDirectory, classFileName, monitor);

		JadProcessWrapper wrapper = new JadProcessWrapper(destClassFile);
		JadProcessController controller = new JadProcessController(wrapper, classGFile.getName());
		controller.decompile(5, monitor);
	}

	private void processXML(File outputDirectory, GFile containerFile, TaskMonitor monitor)
			throws CancelledException {

		try (AndroidXmlFileSystem fs = fsService.mountSpecificFileSystem(containerFile.getFSRL(),
			AndroidXmlFileSystem.class, monitor)) {
			GFile xmlFile = fs.getPayloadFile();
			copyStream(fs.getInputStream(xmlFile, monitor), outputDirectory,
				containerFile.getName(), monitor);
		}
		catch (IOException ioe) {
			Msg.info(this,
				"XML file " + containerFile.getPath() + " is not AndriodXmlFileSystem compatible",
				ioe);
		}
	}

	private static File copyFile(ResourceFile inputFile, File outputDirectory, String outputName,
			TaskMonitor monitor) throws IOException {

		try (InputStream is = inputFile.getInputStream()) {
			FileUtilities.checkedMkdirs(outputDirectory);
			File destFile = new File(outputDirectory, outputName);

			monitor.setMessage("Copying [" + inputFile.getName() + "] to Eclipse project...");
			FileUtilities.copyStreamToFile(is, destFile, false, monitor);

			return destFile;
		}
	}

	private static File copyStream(ByteProvider provider, File outputDirectory,
			String outputName, TaskMonitor monitor) throws IOException {
		return copyStream(provider.getInputStream(0), outputDirectory, outputName, monitor);
	}

	private static File copyStream(InputStream streamToCopy, File outputDirectory,
			String outputName, TaskMonitor monitor) throws IOException {

		try (InputStream is = streamToCopy) {
			FileUtilities.checkedMkdirs(outputDirectory);
			File destFile = new File(outputDirectory, outputName);

			monitor.setMessage("Copying [" + outputName + "] to Eclipse project...");
			FileUtilities.copyStreamToFile(is, destFile, false, monitor);

			return destFile;
		}
	}
}
