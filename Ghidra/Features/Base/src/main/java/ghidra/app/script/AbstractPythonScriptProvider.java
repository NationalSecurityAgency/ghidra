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
import java.util.regex.Pattern;

import generic.jar.ResourceFile;

/**
 * An abstract {@link GhidraScriptProvider} used to provide common functionality to different
 * types of Python script implementations
 */
public abstract class AbstractPythonScriptProvider extends GhidraScriptProvider {

	private static final Pattern BLOCK_COMMENT = Pattern.compile("'''");

	@Override
	public abstract String getDescription();

	@Override
	public abstract String getRuntimeEnvironmentName();

	@Override
	public abstract GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws GhidraScriptLoadException;

	@Override
	public void createNewScript(ResourceFile newScript, String category) throws IOException {
		try (PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)))) {
			writeHeader(writer, category);
			writer.println("");
			writeBody(writer);
			writer.println("");
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * In Python this is a triple single quote sequence, "'''".
	 * 
	 * @return the Pattern for Python block comment openings
	 */
	@Override
	public Pattern getBlockCommentStart() {
		return BLOCK_COMMENT;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * In Python this is a triple single quote sequence, "'''".
	 * 
	 * @return the Pattern for Python block comment openings
	 */
	@Override
	public Pattern getBlockCommentEnd() {
		return BLOCK_COMMENT;
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
	protected String getCertificationBodyPrefix() {
		return "#";
	}

	@Override
	protected String getCertifyHeaderEnd() {
		return "##";
	}

	@Override
	public String getExtension() {
		return ".py";
	}
}
