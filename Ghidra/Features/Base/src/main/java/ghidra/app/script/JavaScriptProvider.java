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
package ghidra.app.script;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import javax.tools.*;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject.Kind;

import org.apache.felix.fileinstall.internal.JarDirUrlHandler;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.osgi.BundleCompiler;
import ghidra.app.script.osgi.BundleHost;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {

	private BundleHost bundle_host = new BundleHost();
	{
		try {
			bundle_host.start_felix();
		}
		catch (BundleException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public String getDescription() {
		return "Java";
	}

	@Override
	public String getExtension() {
		return ".java";
	}

	@Override
	public boolean deleteScript(ResourceFile scriptSource) {
		// Assuming script is in default java package, so using script's base name as class name.
		File clazzFile = getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource));
		clazzFile.delete();
		return super.deleteScript(scriptSource);
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {

		if (writer == null) {
			writer = new NullPrintWriter();
		}

		ScriptBundleInfo bi = getBundleInfoForScript(sourceFile);
		// look for new source files

		List<ResourceFile> newSource = new ArrayList<>();
		List<Path> oldBin = new ArrayList<>();
		BundleHost.visitUpdatedClassFiles(bi.sourceDir, bi.binDir, (sf, bfs) -> {
			if (sf != null) {
				newSource.add(sf);
			}
			if (bfs != null) {
				oldBin.addAll(bfs);
			}
		});

		// there's new source, so uninstall any existing bundle, delete old class files, and recompile
		if (!newSource.isEmpty()) {
			writer.printf("%s has changed: %d new\n", bi.sourceDir.toString(), newSource.size());
			Bundle b = bi.getBundle();
			if (b != null) {
				try {
					bundle_host.synchronousUninstall(b);
				}
				catch (BundleException | InterruptedException e) {
					e.printStackTrace();
					Msg.error(this, "uninstalling bundle", e);
					return null;
				}
			}
			bundle_host.stopBundleWatcher();
			try {
				for (Path bf : oldBin) {
					Files.delete(bf);
				}
			}
			catch (IOException e) {
				e.printStackTrace();
				Msg.error(this, "deleting old binary files", e);
				return null;
			}

			BundleCompiler bc = new BundleCompiler(bundle_host);
			Msg.trace(this, "Compiling script " + sourceFile + " to dir " + bi.binDir);

			try {
				bc.compileToExplodedBundle(bi.sourceDir, bi.binDir, writer);
			}
			catch (IOException e) {
				e.printStackTrace();
				Msg.error(this, "compiling bundle", e);
				return null;
			}

			bundle_host.startBundleWatcher();
		}

		try {
			Bundle b = bundle_host.installExplodedPath(bi.binDir);
			bi.bundleLoc = b.getLocation();
			System.err.printf("new bundle loc is %s\n", bi.bundleLoc);
			b.start();
			if (!bundle_host.waitForBundleStart(bi.bundleLoc)) {
				Msg.error(this, "starting bundle");
				return null;
			}
		}
		catch (InterruptedException | BundleException e) {
			e.printStackTrace();
			Msg.error(this, "starting bundle", e);
			return null;
		}

		Bundle b = bi.getBundle();
		Class<?> clazz = b.loadClass(bi.classNameForScript(sourceFile));
		Object object;
		try {
			object = clazz.getDeclaredConstructor().newInstance();
		}
		catch (IllegalArgumentException | InvocationTargetException | NoSuchMethodException
				| SecurityException e) {
			e.printStackTrace();
			Msg.error(this, "instantiatiating script", e);
			return null;
		}
		if (object instanceof GhidraScript) {
			GhidraScript script = (GhidraScript) object;
			script.setSourceFile(sourceFile);
			return script;
		}

		String message = "Not a valid Ghidra script: " + sourceFile.getName();
		writer.println(message);
		Msg.error(this, message); // the writer may not be the same as Msg, so log it too
		return null; // class is not a script
	}

	/**
	 * Gets the class file corresponding to the given source file and class name. If the class is in a package, the
	 * class name should include the full package name.
	 * 
	 * @param sourceFile The class's source file.
	 * @param className  The class's name (including package if applicable).
	 * @return The class file corresponding to the given source file and class name.
	 */
	protected File getClassFile(ResourceFile sourceFile, String className) {
		ResourceFile resourceFile =
			GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className);

		File file = resourceFile.getFile(false);
		return file;
	}

	private class ScriptBundleInfo {
		final ResourceFile sourceDir;
		final String symbolicName;
		final Path binDir;
		String bundleLoc;

		public ScriptBundleInfo(ResourceFile sourceDir) {
			this.sourceDir = sourceDir;
			this.symbolicName = getSymbolicNameFromSourceDir(sourceDir);
			this.binDir = bundle_host.getCompiledBundlesDir().resolve(symbolicName);

			this.bundleLoc =
				JarDirUrlHandler.PROTOCOL + ":" + binDir.toAbsolutePath().normalize().toString();
		}

		public String classNameForScript(ResourceFile sourceFile) {
			String p;
			try {
				p = sourceFile.getCanonicalPath();
				p = p.substring(1 + sourceDir.getCanonicalPath().length(), p.length() - 5);// relative path less ".java"
				return p.replace(File.separatorChar, '.');
			}
			catch (IOException e) {
				e.printStackTrace();
				return null;
			}
		}

		Bundle getBundle() {
			return bundle_host.getBundle(bundleLoc);
		}
	}

	private ScriptBundleInfo getBundleInfoForScript(ResourceFile sourceFile) {
		ResourceFile bundleDir = getSourceDirectoryForScript(sourceFile);
		if (bundleDir == null) {
			return null;
		}
		return new ScriptBundleInfo(bundleDir);
	}

	static public String getSymbolicNameFromSourceDir(ResourceFile sourceDir) {
		return Integer.toHexString(sourceDir.getAbsolutePath().hashCode());
	}

	public static ResourceFile getSourceDirectoryForScript(ResourceFile sourceFile) {
		String sourcePath = sourceFile.getAbsolutePath();
		for (ResourceFile sourceDir : GhidraScriptUtil.getScriptSourceDirectories()) {
			if (sourcePath.startsWith(sourceDir.getAbsolutePath())) {
				return sourceDir;
			}
		}
		return null;
	}

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		String scriptName = newScript.getName();
		String className = scriptName;
		int dotpos = scriptName.lastIndexOf('.');
		if (dotpos >= 0) {
			className = scriptName.substring(0, dotpos);
		}
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));

		writeHeader(writer, category);

		writer.println("import ghidra.app.script.GhidraScript;");

		for (Package pkg : Package.getPackages()) {
			if (pkg.getName().startsWith("ghidra.program.model.")) {
				writer.println("import " + pkg.getName() + ".*;");
			}
		}

		writer.println("");

		writer.println("public class " + className + " extends GhidraScript {");
		writer.println("");

		writer.println("    public void run() throws Exception {");

		writeBody(writer);

		writer.println("    }");
		writer.println("");
		writer.println("}");
		writer.close();
	}

	@Override
	public String getCommentCharacter() {
		return "//";
	}

	@Deprecated
	private JavaScriptClassLoader loader = new JavaScriptClassLoader();

	@Deprecated
	private void forceClassReload() {
		loader = new JavaScriptClassLoader(); // this forces the script class to be reloaded
	}

	@Deprecated
	protected boolean needsCompile(ResourceFile sourceFile, File classFile) {

		// Need to compile if there is no class file.
		if (!classFile.exists()) {
			return true;
		}

		// Need to compile if the script's source file is newer than its corresponding
		// class file.
		if (sourceFile.lastModified() > classFile.lastModified()) {
			return true;
		}

		// Need to compile if parent classes are not up to date.
		return !areAllParentClassesUpToDate(sourceFile);
	}

	@Deprecated
	private boolean areAllParentClassesUpToDate(ResourceFile sourceFile) {

		List<Class<?>> parentClasses = getParentClasses(sourceFile);
		if (parentClasses == null) {
			// some class is missing!
			return false;
		}

		if (parentClasses.isEmpty()) {
			// nothing to do--no parent class to re-compile
			return true;
		}

		// check each parent for modification
		for (Class<?> clazz : parentClasses) {
			ResourceFile parentFile = getSourceFile(clazz);
			if (parentFile == null) {
				continue; // not sure if this can happen (inner-class, maybe?)
			}

			// Parent class might have a non-default java package, so use class's full name.
			File clazzFile = getClassFile(parentFile, clazz.getName());

			if (parentFile.lastModified() > clazzFile.lastModified()) {
				return false;
			}
		}

		return true;
	}

	@Deprecated
	protected boolean compile(ResourceFile sourceFile, final PrintWriter writer)
			throws ClassNotFoundException {

		ScriptInfo info = GhidraScriptUtil.getScriptInfo(sourceFile);
		info.setCompileErrors(true);

		if (!doCompile(sourceFile, writer)) {
			writer.flush(); // force any error messages out
			throw new ClassNotFoundException("Unable to compile class: " + sourceFile.getName());
		}

		compileParentClasses(sourceFile, writer);

		forceClassReload();

		info.setCompileErrors(false);
		writer.println("Successfully compiled: " + sourceFile.getName());

		return true;
	}

	@Deprecated
	private boolean doCompile(ResourceFile sourceFile, final PrintWriter writer) {

		JavaCompiler javaCompiler = ToolProvider.getSystemJavaCompiler();
		if (javaCompiler == null) {
			String message =
				"Compile failed: java compiler provider not found (you must be using a JDK " +
					"to compile scripts)!";
			writer.println(message);
			Msg.error(this, message); // the writer may not be the same as Msg, so log it too
			return false;
		}

		JavaFileManager fileManager =
			new ResourceFileJavaFileManager(GhidraScriptUtil.getScriptSourceDirectories());

		List<ResourceFileJavaFileObject> list = new ArrayList<>();
		list.add(
			new ResourceFileJavaFileObject(sourceFile.getParentFile(), sourceFile, Kind.SOURCE));

		String outputDirectory =
			GhidraScriptUtil.getScriptCompileOutputDirectory(sourceFile).getAbsolutePath();
		Msg.trace(this, "Compiling script " + sourceFile + " to dir " + outputDirectory);

		List<String> options = new ArrayList<>();
		options.add("-g");
		options.add("-d");
		options.add(outputDirectory);
		options.add("-sourcepath");
		options.add(getSourcePath());
		options.add("-classpath");
		options.add(getClassPath());
		options.add("-proc:none"); // Prevents warning when script imports something that will get compiled

		CompilationTask task = javaCompiler.getTask(writer, fileManager, null, options, null, list);
		return task.call();
	}

	@Deprecated
	private List<Class<?>> getParentClasses(ResourceFile scriptSourceFile) {

		Class<?> scriptClass = getScriptClass(scriptSourceFile);
		if (scriptClass == null) {
			return null; // special signal that there was a problem
		}

		List<Class<?>> parentClasses = new ArrayList<>();
		Class<?> superClass = scriptClass.getSuperclass();
		while (superClass != null) {
			if (superClass.equals(GhidraScript.class)) {
				break; // not interested in the built-in classes
			}
			else if (superClass.equals(HeadlessScript.class)) {
				break; // not interested in the built-in classes
			}
			parentClasses.add(superClass);
			superClass = superClass.getSuperclass();
		}
		return parentClasses;
	}

	@Deprecated
	private Class<?> getScriptClass(ResourceFile scriptSourceFile) {
		String clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile);
		try {
			return Class.forName(clazzName, true, new JavaScriptClassLoader());
		}
		catch (NoClassDefFoundError | ClassNotFoundException e) {
			Msg.error(this, "Unable to find class file for script file: " + scriptSourceFile, e);
		}
		catch (GhidraScriptUnsupportedClassVersionError e) {
			// Unusual Code Alert!: This implies the script was compiled in a newer
			// version of Java. So, just delete the class file and try again.
			ResourceFile classFile = e.getClassFile();
			classFile.delete();
			return null; // trigger re-compile
		}
		return null;
	}

	@Deprecated
	private void compileParentClasses(ResourceFile sourceFile, PrintWriter writer) {

		List<Class<?>> parentClasses = getParentClasses(sourceFile);
		if (parentClasses == null) {
			// this shouldn't happen, as this method is called after the child class is
			// re-compiled and thus, all parent classes should still be there.
			return;
		}

		if (parentClasses.isEmpty()) {
			// nothing to do--no parent class to re-compile
			return;
		}

		//
		// re-compile each class's source file
		//

		// first, reverse the order, so that we compile the highest-level classes first,
		// and then on down, all the way to the script class
		Collections.reverse(parentClasses);

		// next, add back to the list the script that was just compiled, as it may need
		// to be re-compiled after the parent classes are re-compiled
		Class<?> scriptClass = getScriptClass(sourceFile);
		if (scriptClass == null) {
			// shouldn't happen
			return;
		}
		parentClasses.add(scriptClass);

		for (Class<?> parentClass : parentClasses) {
			ResourceFile parentFile = getSourceFile(parentClass);
			if (parentFile == null) {
				continue; // not sure if this can happen (inner-class, maybe?)
			}

			if (!doCompile(parentFile, writer)) {
				Msg.error(this, "Failed to re-compile parent class: " + parentClass);
				return;
			}
		}
	}

	@Deprecated
	private ResourceFile getSourceFile(Class<?> c) {
		// check all script paths for a dir named
		String classname = c.getName();
		String filename = classname.replace('.', '/') + ".java";

		List<ResourceFile> scriptDirs = GhidraScriptUtil.getScriptSourceDirectories();
		for (ResourceFile dir : scriptDirs) {
			ResourceFile possibleFile = new ResourceFile(dir, filename);
			if (possibleFile.exists()) {
				return possibleFile;
			}
		}

		return null;
	}

	@Deprecated
	private String getSourcePath() {
		return GhidraScriptUtil.getScriptSourceDirectories().stream().map(
			f -> f.getAbsolutePath()).collect(Collectors.joining(File.pathSeparator));
	}

	@Deprecated
	private String getClassPath() {
		String scriptBinDirs = GhidraScriptUtil.getScriptBinDirectories().stream().map(
			f -> f.getAbsolutePath()).collect(Collectors.joining(File.pathSeparator));
		return System.getProperty("java.class.path") + File.pathSeparator + scriptBinDirs;
	}

}
