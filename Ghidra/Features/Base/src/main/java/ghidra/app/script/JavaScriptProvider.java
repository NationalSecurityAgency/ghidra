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
import org.osgi.framework.BundleException;

import generic.io.NullPrintWriter;
import generic.jar.ResourceFile;
import ghidra.app.script.osgi.BundleCompiler;
import ghidra.app.script.osgi.BundleHost;
import ghidra.app.script.osgi.BundleHost.SourceBundleInfo;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {
	// XXX embedded OSGi should be a service
	BundleHost _bundle_host;

	private BundleHost getBundleHost() {
		if (_bundle_host == null) {
			_bundle_host = new BundleHost();
			try {
				_bundle_host.start_felix();
			}
			catch (BundleException | IOException e) {
				e.printStackTrace();
			}

		}
		return _bundle_host;
	}

	private SourceBundleInfo getBundleInfoForScript(ResourceFile sourceFile) {
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

		SourceBundleInfo bi = getBundleInfoForScript(sourceFile);

		try {
			bi.udpateFromFilesystem(writer);
		}
		catch (IOException e) {
			e.printStackTrace(writer);
			return null;
		}

		int failing = bi.getFailingSourcesCount();
		int newSourcecount = bi.getNewSourcesCount();
		if (failing > 0 && newSourcecount == 0) {
			writer.printf("%s hasn't changed, with %d file%s failing in previous build(s):\n",
				bi.getSourceDir().toString(), failing, failing > 1 ? "s" : "");
			writer.printf("%s\n", bi.getPreviousBuildErrors());
		}
		if (bi.newManifestFile() && newSourcecount == 0) {
			// XXX if there is a new or updated manifest file, uninstall bundle, copy manifest, and restart bundle
		}

		BundleHost bundle_host = getBundleHost();
		// there's new source, so uninstall any existing bundle, delete old class files, and recompile
		if (newSourcecount > 0) {
			writer.printf("%s has changed: %d new/updated\n", bi.getSourceDir().toString(),
				newSourcecount);

			// if there a bundle is currently active, uninstall it
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

			// once we've committed to recompile and regenerate generated classes, delete the old stuff
			try {
				bi.deleteOldBinaries();
			}
			catch (IOException e) {
				e.printStackTrace(writer);
				Msg.error(this, "deleting old binaries", e);
				return null;
			}

			BundleCompiler bc = new BundleCompiler(bundle_host);
			Msg.trace(this,
				"Compiling bundle dir " + bi.getSourceDir() + " to dir " + bi.getBinDir());

			long startTime = System.nanoTime();
			try {
				bc.compileToExplodedBundle(bi, writer);
			}
			catch (IOException e) {
				e.printStackTrace(writer);
				Msg.error(this, "compiling bundle", e);
				return null;
			}
			finally {
				long endTime = System.nanoTime();
				writer.printf("%3.2f seconds compile time.\n", (endTime - startTime) / 1e9);
			}
		}
		// as much source as possible built, install bundle and start it if necessary
		Bundle b = bi.getBundle();
		try {
			if (b == null) {
				b = bi.install();
			}
			if (b.getState() != Bundle.ACTIVE) {
				b.start();
			}
			if (!bundle_host.waitForBundleStart(bi.getBundleLoc())) {
				Msg.error(this, "unable to start bundle");
				return null;
			}
		}
		catch (InterruptedException | BundleException e) {
			e.printStackTrace();
			Msg.error(this, "starting bundle", e);
			return null;
		}

		String classname = bi.classNameForScript(sourceFile);
		Object object;
		try {
			Class<?> clazz = b.loadClass(classname); // throws ClassNotFoundException
			object = clazz.getDeclaredConstructor().newInstance();
		}
		catch (IllegalArgumentException | InvocationTargetException | NoSuchMethodException
				| SecurityException e) {
			e.printStackTrace();
			Msg.error(this, "instantiatiating script", e);
			return null;
		}
		catch (ClassNotFoundException e) {
			throw new ClassNotFoundException(
				String.format("%s not found in bundle %s", classname, bi.getBinDir().toString()),
				e.getException());
		}

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

	// XXX everything from here down is deprecated but has dependents

	@Deprecated
	protected boolean needsCompile(ResourceFile sourceFile, File classFile) {
		return true;
	}

	@SuppressWarnings("unused")
	@Deprecated
	protected boolean compile(ResourceFile sourceFile, final PrintWriter writer)
			throws ClassNotFoundException {
		return false;
	}

}
