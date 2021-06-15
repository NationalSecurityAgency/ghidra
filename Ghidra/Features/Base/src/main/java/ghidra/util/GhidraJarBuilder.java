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
package ghidra.util;

import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Pattern;
import java.util.zip.*;

import generic.jar.*;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.*;
import ghidra.framework.plugintool.dialog.ExtensionUtils;
import ghidra.util.classfinder.ClassFinder;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;
import utility.application.ApplicationLayout;
import utility.module.ModuleUtilities;

public class GhidraJarBuilder implements GhidraLaunchable {

	private static final String ROOT = "_Root/";
	private static final String ROOT_GHIDRA = "_Root/Ghidra/";

	// this is set in the buildGhidraJar batch/script files
	private static final String INVOCATION_NAME_PROPERTY = "GhidraJarBuilder.Name";
	private List<File> rootGhidraDirs = new ArrayList<>();
	private List<ApplicationModule> allModules;
	private Set<ApplicationModule> includedModules = new HashSet<>();
	private List<FileFilter> filters = new ArrayList<>();
	private String mainClass = "ghidra.JarRun";
	private boolean excludeHelp;
	private List<String> excludedFileExtensions = new ArrayList<>();
	private Pattern extensionPointSuffixPattern;
	private List<String> extensionPointClasses = new ArrayList<>();
	private ClassLoader classLoader;
	private Set<File> processedJars = new HashSet<>();

	public GhidraJarBuilder() {
		// Required for GhidraLaunchable
	}

	public GhidraJarBuilder(ApplicationLayout layout) throws IOException {
		for (ResourceFile file : layout.getApplicationRootDirs()) {
			File rgd = file.getFile(false).getCanonicalFile();
			rootGhidraDirs.add(rgd);
		}
		allModules = findAllModules(layout);
		Collections.sort(allModules);
		for (ApplicationModule module : allModules) {
			if (includeByDefault(module)) {
				includedModules.add(module);
			}
		}

		filters.add(new FileExtensionFilter());
	}

	private boolean includeByDefault(ApplicationModule module) {
		if (module.isFramework() || module.isProcessor() || module.isConfiguration()) {
			return true;
		}
		if (module.isExtension()) {
			return false;
		}
		if (module.isFeature()) {
			// include features unless they have been excluded via the module.manifest file.
			return !module.excludeFromGhidraJar();
		}
		if (module.isDebug()) {
			// include debug modules unless they have been excluded via the module.manifest file.
			return !module.excludeFromGhidraJar();
		}
		if (module.isGPL()) {
			// include features unless they have been excluded via the module.manifest file.
			return !module.excludeFromGhidraJar();
		}
		return false;
	}

	public List<ApplicationModule> getAllModules() {
		ArrayList<ApplicationModule> list = new ArrayList<>(allModules);
		Collections.sort(list);
		return list;
	}

	public List<ApplicationModule> getIncludedModules() {
		ArrayList<ApplicationModule> list = new ArrayList<>(includedModules);
		Collections.sort(list);
		return list;
	}

	public void removeAllProcessorModules() {
		Iterator<ApplicationModule> it = includedModules.iterator();
		while (it.hasNext()) {
			ApplicationModule module = it.next();
			if (module.isProcessor()) {
				it.remove();
			}
		}
	}

	public List<ApplicationModule> getExcludedModules() {
		Set<ApplicationModule> set = new HashSet<>(allModules);
		set.removeAll(includedModules);
		ArrayList<ApplicationModule> list = new ArrayList<>(set);
		Collections.sort(list);
		return list;
	}

	public ApplicationModule getModule(String name) {
		for (ApplicationModule module : allModules) {
			if (module.getName().equals(name)) {
				return module;
			}
		}
		return null;
	}

	public boolean isModuleIncluded(String moduleName) {
		ApplicationModule module = getModule(moduleName);
		return includedModules.contains(module);
	}

	public void addAllModules() {
		includedModules.addAll(allModules);
	}

	public boolean addModule(String name) {
		ApplicationModule module = getModule(name);
		if (module != null) {
			return includedModules.add(module);
		}
		return false;
	}

	public boolean removeModule(String name) {
		ApplicationModule module = getModule(name);
		if (module != null) {
			return includedModules.remove(module);
		}
		return false;
	}

	public void addFileFilter(FileFilter filter) {
		filters.add(filter);
	}

	public void addExcludedFileExtension(String excludedExtension) {
		excludedFileExtensions.add(excludedExtension);
	}

	public void addModuleToJar(ApplicationModule module) {
		includedModules.add(module);
	}

	public void setExcludeHelp(boolean excludeHelp) {
		this.excludeHelp = excludeHelp;
	}

	public void setMainClass(String mainClass) {
		this.mainClass = mainClass;
	}

	public void buildJar(File outputFile, File extraBinDir, TaskMonitor monitor)
			throws IOException, CancelledException {

		Msg.info(this, "Building GHIDRA standalone jar file: " + outputFile);

		createExtensionPointSuffixPattern();

		Manifest manifest = createManifest();
		Jar jar = new Jar(outputFile, manifest, monitor);

		List<ApplicationModule> moduleList = new ArrayList<>(includedModules);

		Collections.sort(moduleList);
		createClassLoader(moduleList);

		if (extraBinDir != null) {
			writeDirRecursively(jar, extraBinDir.getAbsolutePath(), extraBinDir, null);
		}

		for (ApplicationModule module : moduleList) {
			writeModuleClassesAndResources(jar, module);
			if (!excludeHelp) {
				writeModuleHelp(jar, module);
			}
		}

		writeNonModuleFiles(jar);

		jar.setPathPrefix(ROOT_GHIDRA);

		for (ApplicationModule module : moduleList) {
			writeModuleData(jar, module);
		}

		if (extraBinDir != null) {
			processSrcForModuleTree(jar, moduleList);
		}

		jar.writeGhidraExtensionsDir();
		jar.writeExtensionPointClassFile();
		jar.writeModuleListFile(moduleList);
		jar.close();
	}

	private void processSrcForModuleTree(Jar jar, List<ApplicationModule> moduleList) {
		for (ApplicationModule module : moduleList) {
			File srcDir = new File(module.getModuleDir(), "src");
			processSrcRecursively(jar, srcDir, srcDir.getAbsolutePath(), module);
		}
	}

	private void processSrcRecursively(Jar jar, File srcDir, String rootPath,
			ApplicationModule module) {
		if (!srcDir.isDirectory()) {
			return;
		}
		File[] listFiles = srcDir.listFiles();
		for (File file : listFiles) {
			if (file.isDirectory()) {
				processSrcRecursively(jar, file, rootPath, module);
			}
			else if (isJavaFile(file)) {
				String path = getPathFromRoot(rootPath, file);
				// replace .java with .class
				path = path.substring(0, path.length() - 5).concat(".class");
				jar.addToModuleTree(path, module);
			}
		}

	}

	private boolean isJavaFile(File file) {
		return file.getName().endsWith(".java");
	}

	private void createClassLoader(List<ApplicationModule> modules) {
		List<File> moduleDirs = new ArrayList<>();
		for (ApplicationModule module : modules) {
			moduleDirs.add(module.getModuleDir());
		}
		classLoader = new GClassLoader(moduleDirs);
	}

	private void createExtensionPointSuffixPattern() {
		Set<String> suffixes = new HashSet<>();
		for (ApplicationModule module : includedModules) {
			File manifest = new File(module.getModuleDir(), "data/ExtensionPoint.manifest");
			accumulatedExtensionPointSuffixes(suffixes, manifest);
		}
		StringBuilder sb = new StringBuilder();
		sb.append(".*(");
		String between = "";
		for (String suffix : suffixes) {
			suffix = suffix.trim();
			if (suffix.isEmpty()) {
				continue;
			}
			sb.append(between);
			sb.append(suffix);
			between = "|";
		}
		sb.append(")");
		sb.append(".class");
		extensionPointSuffixPattern = Pattern.compile(sb.toString());

	}

	private void accumulatedExtensionPointSuffixes(Set<String> suffixes, File manifest) {
		if (!manifest.exists()) {
			return;
		}

		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(manifest));
			String line;
			while ((line = reader.readLine()) != null) {
				suffixes.add(line);
			}
		}
		catch (Exception e) {
			Msg.error(ClassSearcher.class,
				"Error opening extension point file " + manifest.getAbsolutePath(), e);
		}
		finally {
			if (reader != null) {
				try {
					reader.close();
				}
				catch (IOException e) {
					// oh well
				}
			}
		}

	}

	public void buildSrcZip(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {

		Zip zip = new Zip(outputFile, monitor);
		boolean wroteToZip = false;

		List<ApplicationModule> moduleList = new ArrayList<>(includedModules);
		Collections.sort(moduleList);

		for (ApplicationModule module : moduleList) {
			File srcDir = new File(module.getModuleDir(), "src");
			File srcZipFileForModule = new File(srcDir, module.getName() + "-src.zip");
			if (srcZipFileForModule.exists()) {
				writeModuleSrcZipToOverallSrcZip(zip, srcZipFileForModule);
				wroteToZip = true;
			}
			else {
				wroteToZip |= writeZipRecursively(zip, srcDir.getAbsolutePath(), srcDir);
			}
		}
		if (wroteToZip) {
			System.out
					.println("Can't create source zip!  Has source been downloaded and installed?");
			// zip.close reports error if nothing has been written to it
			zip.close();
		}
	}

	private void writeModuleSrcZipToOverallSrcZip(Zip zip, File srcZipFileForModule)
			throws IOException, CancelledException {

		ZipFile zipFile = new ZipFile(srcZipFileForModule);
		Enumeration<? extends ZipEntry> entries = zipFile.entries();
		while (entries.hasMoreElements()) {
			ZipEntry zipEntry = entries.nextElement();
			if (zipEntry.isDirectory()) {
				continue;
			}
			zip.addZipEntry(zipFile, zipEntry);
		}
	}

	private void writeModuleClassesAndResources(Jar jar, ApplicationModule module)
			throws CancelledException, IOException {

		// NOTE: This only works in a distribution where the 3rd party jars live in each
		// module's libs directory
		File binDir = new File(module.getModuleDir(), "bin/main");
		writeDirRecursively(jar, binDir.getAbsolutePath(), binDir, module);
		File resourceDir = new File(module.getModuleDir(), "src/main/resources");
		writeDirRecursively(jar, resourceDir.getAbsolutePath(), resourceDir, null);

		processLibDir(jar, module);
	}

	private void processLibDir(Jar jar, ApplicationModule module)
			throws CancelledException, IOException {
		File libDir = new File(module.getModuleDir(), "lib");
		if (!libDir.isDirectory()) {
			return;
		}
		File[] listFiles = libDir.listFiles();
		for (File file : listFiles) {
			if (isJar(file)) {
				processJarFile(jar, file, module);
			}
		}
	}

	private void processJarFile(Jar jar, File file, ApplicationModule module)
			throws IOException, CancelledException {
		if (!file.exists()) {
			return;
		}
		if (processedJars.contains(file)) {
			return;
		}
		processedJars.add(file);
		JarFile jarFile = new JarFile(file);
		Enumeration<JarEntry> entries = jarFile.entries();
		while (entries.hasMoreElements()) {
			JarEntry jarEntry = entries.nextElement();
			String jarName = jarEntry.getName();

			// Special case for Log4j:
			//
			//  	Log4j scatters .dat files around in modules that use the log4j
			//		plugin construct. Each one contains the plugins that that module
			//		requires. The problem is that each of these has the exact same path:
			//
			//		META-INF/org/apache/logging/log4j/core/config/plugins/Log4j2Plugins.dat
			//
			//		If we just blindly copy all of them to our new jar, we risk overwriting the
			//		.dat file from the log4j core library (which is the one we really need). To
			//		avoid this, the following code ensures that we only copy the one from the
			//		core jar.
			//
			//  	NOTE: The above statement obviously means that we're dropping the information
			//			contained in the 'other' .dat files. This could cause a problem at some
			//			point, even though it doesn't now. As such, we may want to try to merge
			//			all the .dat files together at some point.
			//
			if (jarName.contains("Log4j2Plugins.dat")) {
				if (jarFile.getName().contains("log4j-core")) {
					jar.addJarEntry(jarFile, jarEntry, module);
				}
				else {
					continue;
				}
			}

			if (jarName.endsWith(".SF") || jarName.endsWith(".DSA") || jarName.endsWith(".RSA")) {
				continue;
			}

			jar.addJarEntry(jarFile, jarEntry, module);
		}
	}

	private boolean isJar(File file) {
		return (file.isFile() && file.getName().endsWith(".jar"));
	}

	private void writeModuleData(Jar jar, ApplicationModule module)
			throws CancelledException, IOException {
		File moduleDir = module.getModuleDir();
		String appRootPath = module.getApplicationRoot().getAbsolutePath();
		File moduleManifestFile = new File(moduleDir, "Module.manifest");
		String jarPath = getPathFromRoot(appRootPath, moduleManifestFile);
		jar.addFile(jarPath, moduleManifestFile, null);

		// Extension properties. If this exists, write it.
		File extensionPropertiesFile = new File(moduleDir, ExtensionUtils.PROPERTIES_FILE_NAME);
		if (extensionPropertiesFile.exists()) {
			jarPath = getPathFromRoot(appRootPath, extensionPropertiesFile);
			jar.addFile(jarPath, extensionPropertiesFile, module);
		}

		// process data dir
		writeDirRecursively(jar, appRootPath, new File(moduleDir, "data"), null);

		// process os dir
		writeDirRecursively(jar, appRootPath, new File(moduleDir, "os"), null);
		writeDirRecursively(jar, appRootPath, new File(moduleDir, "build/os"), null);

		// process scripts directories
		writeDirRecursively(jar, appRootPath, new File(moduleDir, "ghidra_scripts"), null);
		writeDirRecursively(jar, appRootPath, new File(moduleDir, "developer_scripts"), null);

	}

	private void writeModuleHelp(Jar jar, ApplicationModule module)
			throws CancelledException, IOException {
		File moduleDir = module.getModuleDir();
		File helpDir = new File(moduleDir, "help");
		if (!helpDir.isDirectory()) {
			return;
		}
		writeDirRecursively(jar, moduleDir.getAbsolutePath(), new File(helpDir, "shared"), null);
		writeDirRecursively(jar, moduleDir.getAbsolutePath(), new File(helpDir, "topics"), null);
		File helpBinDir = new File(helpDir, "bin/main");
		jar.setPathPrefix("help/");
		writeDirRecursively(jar, helpBinDir.getAbsolutePath(), helpBinDir, null);
		jar.setPathPrefix(null);
	}

	private void writeDirRecursively(Jar jar, String rootPath, File dir, ApplicationModule module)
			throws CancelledException, IOException {
		if (!dir.isDirectory()) {
			return;
		}
		File[] listFiles = dir.listFiles();
		for (File file : listFiles) {
			if (file.isDirectory()) {
				writeDirRecursively(jar, rootPath, file, module);
			}
			else if (passesAllFilters(file)) {
				String jarPath = getPathFromRoot(rootPath, file);
				jar.addFile(jarPath, file, module);
			}
		}
	}

	private boolean writeZipRecursively(Zip zip, String rootPath, File dir)
			throws CancelledException, IOException {
		if (!dir.isDirectory()) {
			return false;
		}
		boolean wroteToZip = false;
		File[] listFiles = dir.listFiles();
		for (File file : listFiles) {
			if (file.isDirectory()) {
				wroteToZip |= writeZipRecursively(zip, rootPath, file);
			}
			else {
				String zipPath = getPathFromRoot(rootPath, file);
				zip.addFile(zipPath, file);
				wroteToZip = true;
			}
		}
		return wroteToZip;
	}

	private boolean passesAllFilters(File file) {
		for (FileFilter filter : filters) {
			if (!filter.accept(file)) {
				return false;
			}
		}
		return true;
	}

	private void writeNonModuleFiles(Jar jar) throws IOException, CancelledException {
		jar.setPathPrefix(ROOT);

		File rootDir = findRootDir();
		File applicatonProperties = getApplicationPropertyFile(rootDir);
		String jarPath =
			getPathFromRoot(rootDir.getParentFile().getAbsolutePath(), applicatonProperties);
		jar.addFile(jarPath, applicatonProperties, null);

		File whatsNew = new File(rootDir, "docs/WhatsNew.html");
		if (whatsNew.exists()) {
			jarPath = getPathFromRoot(rootDir.getAbsolutePath(), whatsNew);
			jar.addFile(jarPath, whatsNew, null);
		}

		File changeHistory = new File(rootDir, "docs/ChangeHistory.html");
		if (changeHistory.exists()) {
			jarPath = getPathFromRoot(rootDir.getAbsolutePath(), changeHistory);
			jar.addFile(jarPath, changeHistory, null);
		}
	}

	private File findRootDir() {
		for (File root : rootGhidraDirs) {
			if (getApplicationPropertyFile(root).exists()) {
				return root;
			}
		}
		throw new AssertException("Can't find application property file!");
	}

	private Manifest createManifest() {
		Manifest manifest = new Manifest();
		Attributes mainAttributes = manifest.getMainAttributes();
		mainAttributes.putValue("Manifest-Version", "1.0");
		if (mainClass != null) {
			mainAttributes.putValue("Main-Class", mainClass);

		}
		return manifest;
	}

	private List<ApplicationModule> findAllModules(ApplicationLayout layout) throws IOException {
		List<ApplicationModule> modules = new ArrayList<>();

		for (GModule module : layout.getModules().values()) {
			File moduleDir = module.getModuleRoot().getFile(false).getCanonicalFile();
			File rootDir = getModuleRootDir(moduleDir);
			modules.add(new ApplicationModule(rootDir, moduleDir));
		}

		return modules;
	}

	private File getModuleRootDir(File moduleDir) {
		// Look in GPL directories too
		List<File> rootDirs = new ArrayList<>(rootGhidraDirs);
		for (File rootDir : rootGhidraDirs) {
			rootDirs.add(new File(rootDir.getParentFile(), "GPL"));
		}

		// Check each root directory to see if it contains the module
		for (File rootDir : rootDirs) {
			if (FileUtilities.isPathContainedWithin(rootDir, moduleDir)) {
				return rootDir;
			}
		}
		throw new AssertException("Module root directory could not be determined: " + moduleDir);
	}

	private String getPathFromRoot(String rootPath, File file) {
		String filePath = file.getAbsolutePath();
		if (!filePath.startsWith(rootPath)) {
			throw new AssertException("Attempted to get jar path for file not under root!");
		}
		return filePath.substring(rootPath.length() + 1);
	}

	private void checkExtensionPointClass(String path, InputStream inputStream) {
		// remove .class
		path = path.substring(0, path.length() - 6);
		path = path.replace('/', '.');
		try {
			Class<?> clazz = classLoader.loadClass(path);
			if (clazz == null) {
				System.out.println("Couldn't load " + path);
			}
			else if (ClassFinder.isClassOfInterest(clazz)) {
				extensionPointClasses.add(clazz.getName());
			}
		}
		catch (ClassNotFoundException e) {
			System.out.println("Can't load class " + path);
		}
		catch (Throwable t) {
			System.out.println("Throwable " + t);
		}
	}

	private class Jar {
		private JarOutputStream jarOut;
		private TaskMonitor monitor;
		private String prefix;
		private ClassModuleTree classTree = new ClassModuleTree();

		Jar(File outputFile, Manifest manifest, TaskMonitor monitor) throws IOException {
			this.monitor = monitor;
			FileOutputStream fos = new FileOutputStream(outputFile);
			jarOut = new JarOutputStream(fos, manifest);
		}

		/**
		 * Puts a directory in the jar for Ghidra Extensions. This may be empty (if
		 * no extensions are installed) but should exist nonetheless.
		 *
		 * @throws IOException if there's an error writing to the jar
		 */
		public void writeGhidraExtensionsDir() throws IOException {
			ZipEntry entry = new ZipEntry(ROOT_GHIDRA + "Extensions/");

			try {
				jarOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}
			finally {
				jarOut.closeEntry();
			}
		}

		public void writeExtensionPointClassFile() throws IOException {
			String s = "abc";
			s.getBytes();

			ZipEntry entry = new ZipEntry(ROOT_GHIDRA + "EXTENSION_POINT_CLASSES");

			try {
				jarOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}
			for (String extensionPointClass : extensionPointClasses) {
				jarOut.write(extensionPointClass.getBytes());
				jarOut.write('\n');
			}

			jarOut.closeEntry();
		}

		public void writeModuleListFile(List<ApplicationModule> moduleList) throws IOException {
			ZipEntry entry = new ZipEntry(ROOT_GHIDRA + ModuleUtilities.MODULE_LIST);

			try {
				jarOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}
			for (ApplicationModule module : moduleList) {
				String relativePath = module.getRelativePath();
				jarOut.write(relativePath.getBytes());
				jarOut.write('\n');
			}

			jarOut.closeEntry();
		}

		public void setPathPrefix(String string) {
			prefix = string;
		}

		public void close() throws IOException {
			File tempFile = File.createTempFile("jarBuilder", "treeIDX");
			classTree.trim();
			classTree.saveFile(tempFile);
			try {
				addFile("classModuleTree", tempFile, null);
			}
			catch (CancelledException e) {
				// don't cares
			}
			tempFile.delete();
			jarOut.close();
		}

		/**
		 * Outputs an individual file to the jar.
		 */
		public void addFile(String jarPath, File file, ApplicationModule module)
				throws IOException, CancelledException {
			if (!file.exists()) {
				throw new AssertException(
					"Attempted to write a file that does not exist to the jar! File = " +
						file.getAbsolutePath());
			}

			if (!file.isFile()) {
				throw new AssertException(
					"Attempted to write a directory to the jar! File = " + file.getAbsolutePath());
			}

			jarPath = jarPath.replaceAll("\\\\", "/"); // handle windows separators

			long modifiedTime = file.lastModified();
			addToModuleTree(jarPath, module);
			if (extensionPointSuffixPattern.matcher(jarPath).matches()) {
				try (FileInputStream inStream = new FileInputStream(file)) {
					checkExtensionPointClass(jarPath, inStream);
				}
			}

			if (prefix != null) {
				jarPath = prefix + jarPath;
			}
			if (jarPath.contains("..")) {
				jarPath = Path.of(jarPath).normalize().toString();
			}

			ZipEntry entry = new ZipEntry(jarPath);
			entry.setTime(modifiedTime);

			try {
				jarOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}

			try (InputStream in = new FileInputStream(file)) {

				byte[] bytes = new byte[4096];
				int numRead;

				while ((numRead = in.read(bytes)) != -1) {
					monitor.checkCanceled();
					jarOut.write(bytes, 0, numRead);
				}
			}

			jarOut.closeEntry();

		}

		public void addJarEntry(JarFile jarFile, JarEntry jarEntry, ApplicationModule module)
				throws IOException, CancelledException {
			long modifiedTime = jarEntry.getTime();
			String path = jarEntry.getName();
			if (extensionPointSuffixPattern.matcher(path).matches()) {
				checkExtensionPointClass(path, jarFile.getInputStream(jarEntry));
			}

			addToModuleTree(path, module);
			ZipEntry entry = new ZipEntry(path);
			entry.setTime(modifiedTime);
			try {
				jarOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}

			InputStream in = jarFile.getInputStream(jarEntry);

			byte[] bytes = new byte[4096];
			int numRead;

			while ((numRead = in.read(bytes)) != -1) {
				monitor.checkCanceled();
				jarOut.write(bytes, 0, numRead);
			}
			in.close();

			jarOut.closeEntry();
		}

		private void addToModuleTree(String path, ApplicationModule module) {
			if (module == null) {
				return;
			}
			if (path.endsWith(".class")) {
				classTree.addNode(path, module.getName());
			}
		}

	}

	private class Zip {
		private ZipOutputStream zipOut;
		private TaskMonitor monitor;

		Zip(File outputFile, TaskMonitor monitor) throws IOException {
			this.monitor = monitor;
			FileOutputStream fos = new FileOutputStream(outputFile);
			zipOut = new ZipOutputStream(fos);
		}

		public void close() throws IOException {
			zipOut.close();
		}

		/**
		 * Outputs an individual file to the jar.
		 */
		public void addFile(String zipPath, File file) throws IOException, CancelledException {
			if (!file.isFile()) {
				throw new AssertException("Attempted to write a directory to the jar file");
			}

			zipPath = zipPath.replaceAll("\\\\", "/"); // handle windows separators

			long modifiedTime = file.lastModified();

			ZipEntry entry = new ZipEntry(zipPath);
			entry.setTime(modifiedTime);

			try {
				zipOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}

			InputStream in = new FileInputStream(file);

			byte[] bytes = new byte[4096];
			int numRead;

			while ((numRead = in.read(bytes)) != -1) {
				monitor.checkCanceled();
				zipOut.write(bytes, 0, numRead);
			}
			in.close();

			zipOut.closeEntry();

		}

		public void addZipEntry(ZipFile zipFile, ZipEntry zipEntry)
				throws IOException, CancelledException {
			long modifiedTime = zipEntry.getTime();
			String path = zipEntry.getName();

			ZipEntry entry = new ZipEntry(path);
			entry.setTime(modifiedTime);
			try {
				zipOut.putNextEntry(entry);
			}
			catch (ZipException e) {
				System.out.println(e.getMessage());
				return;
			}

			InputStream in = zipFile.getInputStream(zipEntry);

			byte[] bytes = new byte[4096];
			int numRead;

			while ((numRead = in.read(bytes)) != -1) {
				monitor.checkCanceled();
				zipOut.write(bytes, 0, numRead);
			}
			in.close();

			zipOut.closeEntry();
		}

	}

	private class FileExtensionFilter implements FileFilter {
		@Override
		public boolean accept(File file) {
			for (String excludedExtension : excludedFileExtensions) {
				if (file.getName().endsWith(excludedExtension)) {
					return false;
				}
			}
			return true;
		}
	}

	private static void usage(String[] args) {
		for (int i = 0; i < args.length; i++) {
			System.err.println("arg " + i + ": " + args[i]);
		}
		String invocationName = System.getProperty(INVOCATION_NAME_PROPERTY);

		StringBuffer buf = new StringBuffer();
		buf.append("\nUsage: ");
		buf.append(invocationName != null ? invocationName : "GhidraJarBuilder");
		buf.append(
			" [-output <output file>] [-srczip <src zip output file>] [-bin <compiled classes dir>] [-main <main-class>]\n");
		System.err.println(buf.toString());
		System.exit(0);
	}

	/**
	 * Entry point for 'gradle buildGhidraJar'.
	 */
	public static void main(String[] args) throws IOException {
		new GhidraJarBuilder().launch(new GhidraApplicationLayout(), args);
	}

	/**
	 * Entry point for buildGhidraJar.bat.
	 */
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws IOException {
		Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
		if (args.length == 0) {
			usage(args);
		}

		File outputFile = null;
		File srczip = null;
		File extraBinDir = null;
		String mainClassArg = null;

		for (int i = 0; i < args.length; i++) {
			String arg = args[i];
			if (arg.equals("-output")) {
				if (i == args.length - 1) {
					usage(args);
				}
				outputFile = new File(args[++i]);
			}
			else if (arg.equals("-srczip")) {
				if (i == args.length - 1) {
					usage(args);
				}
				srczip = new File(args[++i]);
			}
			else if (arg.equals("-bin")) {
				if (i == args.length - 1) {
					usage(args);
				}
				extraBinDir = new File(args[++i]);
			}
			else if (arg.equals("-main")) {
				if (i == args.length - 1) {
					usage(args);
				}
				mainClassArg = args[++i];
			}
			else {
				usage(args);
			}
		}
		if (outputFile == null) {
			outputFile = new File("ghidra.jar");
		}

		System.out.println("Output file = " + outputFile);
		if (srczip != null) {
			System.out.println("Source Zip File = " + srczip);
		}
		if (extraBinDir != null) {
			System.out.println("Extra Bin Dir = " + extraBinDir);
		}

		try {
			GhidraJarBuilder builder = new GhidraJarBuilder(layout);
			if (mainClassArg != null) {
				builder.setMainClass(mainClassArg);
			}
			builder.addExcludedFileExtension(".pdf");

//		builder.addExcludedFileExtension(".htm");
//		builder.addExcludedFileExtension(".html");
//		builder.addAllModules();
			List<ApplicationModule> moduleList = builder.getIncludedModules();
			for (ApplicationModule module : moduleList) {
				System.out.println("Include " + module.getName());
			}
			moduleList = builder.getExcludedModules();
			for (ApplicationModule module : moduleList) {
				System.out.println("Exclude " + module.getName());
			}

			builder.buildJar(outputFile, extraBinDir, TaskMonitor.DUMMY);

			if (srczip != null) {
				builder.buildSrcZip(srczip, TaskMonitor.DUMMY);
			}
		}
		catch (Exception e) {
			System.err.println("Exception build ghidra jar");
			e.printStackTrace();
		}
		System.out.println("Done");
	}

	private static File getApplicationPropertyFile(File ghidraRootDir) {
		return new File(ghidraRootDir, "application.properties");
	}

}
