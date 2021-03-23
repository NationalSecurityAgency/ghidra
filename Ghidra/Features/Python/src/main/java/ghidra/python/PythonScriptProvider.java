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
package ghidra.python;

import java.io.*;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;

public class PythonScriptProvider extends GhidraScriptProvider {

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));
		writeHeader(writer, category);
		writer.println("");
		writeBody(writer);
		writer.println("");
		writer.close();
	}

	@Override
	public String getCommentCharacter() {
		return "#";
	}

	@Override
	protected String getCertifyHeaderStart() {
		return "## ###";
	}

	@Override
	protected String getCertifyHeaderEnd() {
		return "##";
	}

	@Override
	protected String getCertificationBodyPrefix() {
		return "#";
	}

	@Override
	public String getDescription() {
		return "Python";
	}

	@Override
	public String getExtension() {
		return ".py";
	}

	@Override
	public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException {

		Class<?> clazz = Class.forName(PythonScript.class.getName());
		GhidraScript script = (GhidraScript) clazz.newInstance();
		script.setSourceFile(sourceFile);
		return script;
	}
}
