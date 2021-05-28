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

import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Pattern;

import generic.jar.ResourceFile;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * NOTE:  ALL GhidraScriptProvider CLASSES MUST END IN "ScriptProvider".  If not,
 * the ClassSearcher will not find them.
 *
 */
public abstract class GhidraScriptProvider
		implements ExtensionPoint, Comparable<GhidraScriptProvider> {

	@Override
	public String toString() {
		return getDescription();
	}

	@Override
	public int hashCode() {
		return getDescription().hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof GhidraScriptProvider) {
			GhidraScriptProvider that = (GhidraScriptProvider) obj;
			return this.getDescription().equals(that.getDescription());
		}
		return false;
	}

	@Override
	public int compareTo(GhidraScriptProvider that) {
		return this.getDescription().compareToIgnoreCase(that.getDescription());
	}

	/**
	 * Deletes the script file and unloads the script from the script manager.
	 * @param scriptSource the script source file
	 * @return true if the script was completely deleted and cleaned up
	 */
	public boolean deleteScript(ResourceFile scriptSource) {
		return !scriptSource.exists() || scriptSource.delete();
	}

	/**
	 * Returns a description for this type of script.
	 * @return a description for this type of script
	 */
	public abstract String getDescription();

	/**
	 * Returns the file extension for this type of script.
	 * For example, ".java" or ".py".
	 * @return the file extension for this type of script
	 */
	public abstract String getExtension();

	/**
	 * Returns a GhidraScript instance for the specified source file.
	 * @param sourceFile the source file
	 * @param writer the print writer to write warning/error messages
	 * @return a GhidraScript instance for the specified source file
	 * @throws ClassNotFoundException if the script class cannot be found
	 * @throws InstantiationException if the construction of the script fails for some reason
	 * @throws IllegalAccessException if the class constructor is not accessible
	 */
	public abstract GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
			throws ClassNotFoundException, InstantiationException, IllegalAccessException;

	/**
	 * Creates a new script using the specified file.
	 * @param newScript the new script file
	 * @param category the script category
	 * @throws IOException if an error occurs writing the file
	 */
	public abstract void createNewScript(ResourceFile newScript, String category)
			throws IOException;

	/**
	 * Returns a Pattern that matches block comment openings.
	 * If block comments are not supported by this provider, then this returns null.
	 * @return the Pattern for block comment openings, null if block comments are not supported
	 */
	public Pattern getBlockCommentStart() {
		return null;
	}

	/**
	 * Returns a Pattern that matches block comment closings.
	 * If block comments are not supported by this provider, then this returns null.
	 * @return the Pattern for block comment closings, null if block comments are not supported
	 */
	public Pattern getBlockCommentEnd() {
		return null;
	}

	/**
	 * Returns the comment character.
	 * For example, "//" or "#".
	 * @return the comment character
	 */
	public abstract String getCommentCharacter();

	/**
	 * Writes the script header. 
	 * Include a place holder for each meta-data item.
	 * @param writer the print writer
	 * @param category the default category
	 */
	protected void writeHeader(PrintWriter writer, String category) {
		if (category == null) {
			category = "_NEW_";
		}

		writer.println(getCommentCharacter() + "TODO write a description for this script");

		for (String metadataItem : ScriptInfo.METADATA) {
			writer.print(getCommentCharacter() + metadataItem + " ");

			if (metadataItem.equals(ScriptInfo.AT_CATEGORY)) {
				writer.print(category);
			}

			writer.println("");
		}

		writer.println("");
	}

	/**
	 * Writes the script body template.
	 * @param writer the print writer
	 */
	protected void writeBody(PrintWriter writer) {
		writer.println(getCommentCharacter() + "TODO Add User Code Here");
	}

	/**
	 * Fixup a script name for searching in script directories.
	 *
	 * <p>This method is part of a poorly specified behavior that is due for future amendment, 
	 * see {@link GhidraScriptUtil#fixupName(String)}.
	 * 
	 * @param scriptName the name of the script, must end with this provider's extension
	 * @return a (relative) file path to the corresponding script
	 */
	@Deprecated
	protected String fixupName(String scriptName) {
		return scriptName;
	}

	/**
	 * Return the start of certification header line if this file type is subject to certification.
	 * @return start of certification header or null if not supported
	 */
	protected String getCertifyHeaderStart() {
		return null;
	}

	/**
	 * Return the prefix for each certification header body line if this file is subject to 
	 * certification.
	 * @return certification header body prefix or null if not supported
	 */
	protected String getCertificationBodyPrefix() {
		return null;
	}

	/**
	 * Return the end of certification header line if this file type is subject to certification.
	 * @return end of certification header or null if not supported
	 */
	protected String getCertifyHeaderEnd() {
		return null;
	}
}
