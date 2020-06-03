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
import java.util.*;
import java.util.stream.Collectors;

import javax.tools.*;
import javax.tools.JavaCompiler.CompilationTask;
import javax.tools.JavaFileObject.Kind;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {

	private JavaScriptClassLoader loader = new JavaScriptClassLoader();

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

		// Assuming script is in default java package, so using script's base name as class name.
		String clazzName = GhidraScriptUtil.getBaseName(sourceFile);
		File clazzFile = getClassFile(sourceFile, clazzName);

		// Compile the source file and its dependencies.  Compilation will only occur if necessary.
		compile(sourceFile, clazzFile, writer); // may throw an exception

		Class<?> clazz = null;
		try {
			clazz = Class.forName(clazzName, true, loader);
		}
		catch (GhidraScriptUnsupportedClassVersionError e) {
			// Unusual Code Alert!: This implies the script was compiled in a newer
			// version of Java.  So, just delete the class file and try again.
			ResourceFile classFile = e.getClassFile();
			classFile.delete();
			return getScriptInstance(sourceFile, writer);
		}

		Object object = clazz.newInstance();
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

	private void forceClassReload() {
		loader = new JavaScriptClassLoader(); // this forces the script class to be reloaded
	}

	/**
	 * Gets the class file corresponding to the given source file and class name.  
	 * If the class is in a package, the class name should include the full 
	 * package name.
	 * 
	 * @param sourceFile The class's source file.
	 * @param className The class's name (including package if applicable).
	 * @return The class file corresponding to the given source file and class name. 
	 */
	protected File getClassFile(ResourceFile sourceFile, String className) {
		ResourceFile resourceFile =
			GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className);

		File file = resourceFile.getFile(false);
		return file;
	}

	protected boolean needsCompile(ResourceFile sourceFile, File classFile) {

		// Need to compile if there is no class file.
		if (!classFile.exists()) {
			return true;
		}

		// Need to compile if the script's source file is newer than its corresponding class file.
		return sourceFile.lastModified() > classFile.lastModified();
	}

	protected void compile(ResourceFile sourceFile, File classFile, final PrintWriter writer)
			throws ClassNotFoundException {

		ScriptInfo info = GhidraScriptUtil.getScriptInfo(sourceFile);
		info.setCompileErrors(true);
		
		// Compile primary source file (if necessary)
		if (needsCompile(sourceFile, classFile)) {
			if (!doCompile(sourceFile, writer)) {
				writer.flush(); // force any error messages out
				throw new ClassNotFoundException(
					"Unable to compile class: " + sourceFile.getName());
			}
			writer.println("Successfully compiled: " + sourceFile.getName());
		}

		// Compile dependent source files (if necessary)
		Set<String> processedClasses = new HashSet<>();
		Queue<String> pendingClasses = new LinkedList<>(findDependencies(classFile));
		while (!pendingClasses.isEmpty()) {
			String depClassName = pendingClasses.remove();
			if (processedClasses.contains(depClassName)) {
				continue;
			}
			ResourceFile depSourceFile = findDependentSourceFile(depClassName);
			if (depSourceFile != null) {
				File depClassFile = getClassFile(depSourceFile, depClassName);
				if (needsCompile(depSourceFile, depClassFile)) {
					if (!doCompile(depSourceFile, writer)) {
						writer.flush(); // force any error messages out
						throw new ClassNotFoundException(
							"Unable to compile class: " + depSourceFile.getName());
					}
					writer.println("Successfully compiled: " + depSourceFile.getName());
				}
				processedClasses.add(depClassName);
				pendingClasses.addAll(findDependencies(depClassFile));
			}
		}
		
		forceClassReload();
		info.setCompileErrors(false);
	}

	/**
	 * Finds the dependent class names (including package) of the given class file.
	 * 
	 * @param classFile The class file to find the dependencies of
	 * @return A {@link Collection} of dependent class names (name includes package)
	 */
	private Collection<String> findDependencies(File classFile) {
		List<String> deps = new ArrayList<>();

		Optional<java.util.spi.ToolProvider> jdeps = java.util.spi.ToolProvider.findFirst("jdeps");
		if (jdeps.isEmpty()) {
			Msg.error(this, "Failed to locate jdeps tool");
			return deps;
		}

		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		ByteArrayOutputStream errStream = new ByteArrayOutputStream();

		try (PrintStream out = new PrintStream(outStream);
				PrintStream err = new PrintStream(errStream)) {
			int exitCode = jdeps.get()
					.run(out, err, "--multi-release", "11", "-v", "-cp", getClassPath(),
						classFile.getAbsolutePath());
			if (exitCode != 0) {
				Msg.error(this, "jdeps returned with exit code " + exitCode);
				Msg.error(this, errStream.toString());
				return deps;
			}
			for (String line : outStream.toString().split("[\\r\\n]+")) {
				if (!line.startsWith(" ")) {
					continue;
				}
				String[] parts = line.trim().split("\\s+", 4);
				if (parts.length == 4 && parts[1].equals("->")) {
					deps.add(parts[2]);
				}
			}
		}

		return deps;
	}

	/**
	 * Finds the given class name's corresponding source file from the set of script source
	 * directories.
	 * 
	 * @param className The name of the class who's source file to find
	 * @return The given class name's corresponding source file from the set of script source
	 *   directories.
	 */
	private ResourceFile findDependentSourceFile(String className) {
		for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
			ResourceFile sourceFile = new ResourceFile(dir, className.replace('.', '/') + ".java");
			if (sourceFile.isFile()) {
				return sourceFile;
			}
		}
		return null;
	}

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

	private String getSourcePath() {
		return GhidraScriptUtil.getScriptSourceDirectories()
				.stream()
				.map(f -> f.getAbsolutePath())
				.collect(Collectors.joining(File.pathSeparator));
	}

	private String getClassPath() {
		String scriptBinDirs = GhidraScriptUtil.getScriptBinDirectories()
				.stream()
				.map(f -> f.getAbsolutePath())
				.collect(Collectors.joining(File.pathSeparator));
		return System.getProperty("java.class.path") + File.pathSeparator + scriptBinDirs;
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
}
