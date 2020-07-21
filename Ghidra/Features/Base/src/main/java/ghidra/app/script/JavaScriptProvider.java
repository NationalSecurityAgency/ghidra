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
import java.util.Collections;

import org.osgi.framework.Bundle;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class JavaScriptProvider extends GhidraScriptProvider {
	private final BundleHost bundleHost;

	/**
	 * Create a new {@link JavaScriptProvider} associated with the current bundle host used by scripting.
	 */
	public JavaScriptProvider() {
		bundleHost = GhidraScriptUtil.getBundleHost();
	}

	/**
	 * Get the {@link GhidraSourceBundle} containing the given source file, assuming it already exists.
	 * 
	 * @param sourceFile the source file
	 * @return the bundle
	 */
	public GhidraSourceBundle getBundleForSource(ResourceFile sourceFile) {
		ResourceFile sourceDir = GhidraScriptUtil.findSourceDirectoryContaining(sourceFile);
		if (sourceDir == null) {
			return null;
		}
		return (GhidraSourceBundle) bundleHost.getExistingGhidraBundle(sourceDir);
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
		try {
			Bundle osgiBundle = getBundleForSource(sourceFile).getOSGiBundle();
			if (osgiBundle != null) {
				bundleHost.deactivateSynchronously(osgiBundle);
			}
		}
		catch (GhidraBundleException e) {
			Msg.error(this, "Error while deactivating bundle for delete", e);
			return false;
		}
		return super.deleteScript(sourceFile);
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {
		try {
			Class<?> clazz = loadClass(sourceFile, writer);
			Object object;
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
		catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
			throw e;
		}
		catch (Exception e) {
			throw new ClassNotFoundException("", e);
		}
	}

	/**
	 * Activate and build the {@link GhidraSourceBundle} containing {@code sourceFile} 
	 * then load the script's class from its class loader. 
	 * 
	 * @param sourceFile the source file
	 * @param writer the target for build messages
	 * @return the loaded {@link Class} object
	 * @throws Exception if build, activation, or class loading fail
	 */
	public Class<?> loadClass(ResourceFile sourceFile, PrintWriter writer) throws Exception {
		GhidraSourceBundle bundle = getBundleForSource(sourceFile);
		bundleHost.activateAll(Collections.singletonList(bundle), TaskMonitor.DUMMY, writer);

		String classname = bundle.classNameForScript(sourceFile);
		Class<?> clazz = bundle.getOSGiBundle().loadClass(classname); // throws ClassNotFoundException
		return clazz;
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
