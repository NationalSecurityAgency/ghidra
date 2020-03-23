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

import org.osgi.framework.Bundle;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.osgi.*;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {
	// XXX embedded OSGi should be a service
	BundleHost _bundle_host;

	private BundleHost getBundleHost() {
		if (_bundle_host == null) {
			_bundle_host = new BundleHost();
			try {
				_bundle_host.startFelix();
			}
			catch (OSGiException | IOException e) {
				throw new RuntimeException(e);
			}
		}
		return _bundle_host;
	}

	public SourceBundleInfo getBundleInfoForScript(ResourceFile sourceFile) {
		ResourceFile sourceDir = getSourceDirectoryForScript(sourceFile);
		if (sourceDir == null) {
			return null;
		}
		return getBundleHost().getSourceBundleInfo(sourceDir);
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
	public boolean deleteScript(ResourceFile sourceFile) {
		Bundle b = getBundleInfoForScript(sourceFile).getBundle();
		if (b != null) {
			try {
				getBundleHost().synchronousUninstall(b);
			}
			catch (GhidraBundleException | InterruptedException e) {
				e.printStackTrace();
				Msg.error(this, "while stopping script's bundle to delete it", e);
				return false;
			}
		}
		return super.deleteScript(sourceFile);
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {

		if (writer == null) {
			writer = new NullPrintWriter();
		}

		try {

			SourceBundleInfo bi = getBundleInfoForScript(sourceFile);

			bi.updateFromFilesystem(writer);

			// needsCompile => needsBundleActivate
			boolean needsCompile = false;
			boolean needsBundleActivate = false;

			int failing = bi.getFailingSourcesCount();
			int newSourcecount = bi.getNewSourcesCount();

			long lastBundleActivation = 0; // XXX record last bundle activation in pathmanager
			if (failing > 0 && (lastBundleActivation > bi.getLastCompileAttempt())) {
				needsCompile = true;
			}

			if (newSourcecount == 0) {
				if (failing > 0) {
					writer.printf(
						"%s hasn't changed, with %d file%s failing in previous build(s):\n",
						bi.getSourceDir().toString(), failing, failing > 1 ? "s" : "");
					writer.printf("%s\n", bi.getPreviousBuildErrors());
				}
				if (bi.newManifestFile()) {
					needsCompile = true;
				}
			}
			else {
				needsCompile = true;
			}

			needsBundleActivate |= needsCompile;

			BundleHost bundle_host = getBundleHost();
			if (needsBundleActivate) {
				writer.printf("%s has %d new/updated %d failed in previous build(s)%s\n",
					bi.getSourceDir().toString(), newSourcecount, failing,
					bi.newManifestFile() ? " and the manifest is new" : "");

				// if there a bundle is currently active, uninstall it
				Bundle b = bi.getBundle();
				if (b != null) {
					bundle_host.synchronousUninstall(b);
				}

				// once we've committed to recompile and regenerate generated classes, delete the old stuff
				if (needsCompile) {
					bi.deleteOldBinaries();

					BundleCompiler bc = new BundleCompiler(bundle_host);

					long startTime = System.nanoTime();
					bc.compileToExplodedBundle(bi, writer);
					long endTime = System.nanoTime();
					writer.printf("%3.2f seconds compile time.\n", (endTime - startTime) / 1e9);
				}
			}
			// as much source as possible built, install bundle and start it if necessary
			Bundle b = bi.getBundle();
			if (b == null) {
				b = bi.install();
				needsBundleActivate = true;
			}

			if (needsBundleActivate) {
				bundle_host.synchronousStart(b);
			}

			String classname = bi.classNameForScript(sourceFile);
			Object object;
			Class<?> clazz = b.loadClass(classname); // throws ClassNotFoundException
			object = clazz.getDeclaredConstructor().newInstance();

			if (object instanceof GhidraScript) {
				GhidraScript script = (GhidraScript) object;
				script.setSourceFile(sourceFile);
				return script;
			}

			String message = "Not a valid Ghidra script: " + sourceFile.getName();
			writer.println(message);
			Msg.error(this, message);
			return null; // class is not GhidraScript
		}
		catch (NoSuchMethodException | IOException | IllegalArgumentException
				| InvocationTargetException | SecurityException | InterruptedException
				| OSGiException e) {
			// XXX getScriptInstance only distinguishes exception to print one of three messages.
			throw new ClassNotFoundException("", e);
		}
	}

	/**
	 * Gets the class file corresponding to the given source file and class name. If the class is in a package, the
	 * class name should include the full package name.
	 * 
	 * @param sourceFile The class's source file.
	 * @param className  The class's name (including package if applicable).
	 * @return The class file corresponding to the given source file and class name.
	 */
	@Deprecated
	protected File getClassFile(ResourceFile sourceFile, String className) {
		ResourceFile resourceFile =
			GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className);

		File file = resourceFile.getFile(false);
		return file;
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

	/**
	 * compile sourcefile and test that the corresponding class is loadable.
	 * 
	 * @param sourceFile path to Java source file
	 * @param writer for messages to user
	 * @return true if compilation succeeded and script can be loaded
	 * @deprecated compilation of a single script doesn't make sense anymore, directories are compiled to bundles.
	 * 
	 */
	@Deprecated
	protected boolean compile(ResourceFile sourceFile, final PrintWriter writer) {
		try {
			return getScriptInstance(sourceFile, writer) != null;
		}
		catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Deprecated
	protected boolean needsCompile(ResourceFile sourceFile, File classFile) {
		return true;
	}

}
