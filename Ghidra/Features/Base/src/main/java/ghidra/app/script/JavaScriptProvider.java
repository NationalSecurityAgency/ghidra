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

import org.osgi.framework.Bundle;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.*;
import ghidra.util.Msg;

public class JavaScriptProvider extends GhidraScriptProvider {
	final private BundleHost _bundleHost;

	public JavaScriptProvider() {
		_bundleHost = GhidraScriptUtil.getBundleHost();
	}

	public GhidraSourceBundle getBundleForSource(ResourceFile sourceFile) {
		ResourceFile sourceDir = GhidraScriptUtil.getSourceDirectoryContaining(sourceFile);
		if (sourceDir == null) {
			return null;
		}
		return (GhidraSourceBundle) _bundleHost.getExistingGhidraBundle(sourceDir);
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
				_bundleHost.deactivateSynchronously(osgiBundle);
			}
		}
		catch (GhidraBundleException | InterruptedException e) {
			e.printStackTrace();
			Msg.error(this, "while deactivating bundle for delete", e);
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

	public Class<?> loadClass(ResourceFile sourceFile, PrintWriter writer) throws Exception {
		GhidraSourceBundle gb = getBundleForSource(sourceFile);
		gb.build(writer);
		
		Bundle b = _bundleHost.install(gb);

		_bundleHost.activateSynchronously(b);

		String classname = gb.classNameForScript(sourceFile);
		Class<?> clazz = b.loadClass(classname); // throws ClassNotFoundException
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
