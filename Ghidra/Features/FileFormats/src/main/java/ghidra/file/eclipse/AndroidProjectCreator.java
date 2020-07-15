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

	private GFile apkFile;
	private File eclipseProjectDirectory;
	private File srcDirectory;
	private File genDirectory;
	private File assetDirectory;

	private ResourceFile projectTemplateFile =
		new ResourceFile(androidDirectory, "eclipse-project");
	private ResourceFile classpathTemplateFile =
		new ResourceFile(androidDirectory, "eclipse-classpath");

	private MessageLog log = new MessageLog();

	public AndroidProjectCreator(GFile apkFile, File eclipseProjectDirectory) {
		this.apkFile = apkFile;
		this.eclipseProjectDirectory = eclipseProjectDirectory;
	}

	public void create(TaskMonitor monitor) throws IOException, CancelledException {
		createEclipseProjectDirectories();

		try (ZipFileSystem fs = FileSystemService.getInstance()
				.mountSpecificFileSystem(
					apkFile.getFSRL(), ZipFileSystem.class, monitor)) {
			List<GFile> listing = fs.getListing(null);
			processListing(eclipseProjectDirectory, listing, monitor);
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
				nameElement.setText(apkFile.getName());
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

	private void processListing(File outputDirectory, List<GFile> listing, TaskMonitor monitor)
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
				processListing(subDir, child.getListing(), monitor);
				continue;
			}

			File cacheFile = FileSystemService.getInstance().getFile(child.getFSRL(), monitor);
			try {
				if (childName.endsWith(".xml") &&
					AndroidXmlFileSystem.isAndroidXmlFile(cacheFile, monitor)) {
					processXML(outputDirectory, child, monitor);
				}
				else if (childName.endsWith("classes.dex")) {
					processDex(outputDirectory, child, monitor);
				}
				else if (childName.endsWith("resources.arsc")) {
					//TODO convert resources file back into actual resources
					copyFile(cacheFile, outputDirectory, child.getName(), monitor);
				}
				else if (childName.endsWith(".class")) {
					processClass(outputDirectory, child, monitor);
				}
				else {
					copyFile(cacheFile, outputDirectory, childName, monitor);
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
		try (DexToJarFileSystem fs = FileSystemService.getInstance()
				.mountSpecificFileSystem(
					dexFile.getFSRL(), DexToJarFileSystem.class, monitor)) {
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

		File classFile = FileSystemService.getInstance().getFile(classGFile.getFSRL(), monitor);
		copyFile(classFile, outputDirectory, classFileName, monitor);

		JadProcessWrapper wrapper = new JadProcessWrapper(destClassFile);
		JadProcessController controller = new JadProcessController(wrapper, classGFile.getName());
		controller.decompile(5, monitor);
	}

	private void processXML(File outputDirectory, GFile containerFile, TaskMonitor monitor)
			throws CancelledException {

		try (AndroidXmlFileSystem fs = FileSystemService.getInstance()
				.mountSpecificFileSystem(
					containerFile.getFSRL(), AndroidXmlFileSystem.class, monitor)) {
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

	private static File copyFile(File inputFile, File outputDirectory, String outputName,
			TaskMonitor monitor) throws IOException {

		FileUtilities.checkedMkdirs(outputDirectory);
		File destFile = new File(outputDirectory, outputName);

		monitor.setMessage("Copying [" + inputFile.getName() + "] to Eclipse project...");
		FileUtilities.copyFile(inputFile, destFile, false, monitor);

		return destFile;
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
