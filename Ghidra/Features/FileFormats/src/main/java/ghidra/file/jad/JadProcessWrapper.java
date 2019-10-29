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
package ghidra.file.jad;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.Application;
import ghidra.framework.Platform;

/**
 * Wrapper class for JAD, a JAva Decompiler.
 */
public class JadProcessWrapper {

	public boolean shouldDecompileDeadCode = true;
	public boolean shouldInsertNewLineBeforeOpeningBrace = false;
	public boolean shouldOutputFieldsBeforeMethods = true;
	public boolean shouldOutputSpaceBetweenKeywords = true;
	public boolean shouldOverwriteOutputFiles = true;
	public boolean shouldRestoreDirectoryStructure = false;
	public boolean shouldUseTabsForIndentation = true;
	public boolean verbose = false;

	public Radix radix = Radix.SIXTEEN;
	public String outputFileExtension = "java";
	public File outputDirectory;

	private File file;

	public JadProcessWrapper(File file) {
		this.file = file;
	}

	public File getInputDirectory() {
		return file;
	}

	public File getWorkingDirectory() {
		if (file.isDirectory()) {
			return file;
		}
		return file.getParentFile();
	}

	public String[] getCommands() throws IOException {

		List<String> list = new ArrayList<>();

		list.add(getJadPath());

		if (shouldDecompileDeadCode) {
			list.add("-dead");
		}

		if (shouldOutputFieldsBeforeMethods) {
			list.add("-ff");
		}

		if (!shouldInsertNewLineBeforeOpeningBrace) {
			list.add("-nonlb");
		}

		if (shouldOverwriteOutputFiles) {
			list.add("-o");
		}

		if (shouldRestoreDirectoryStructure) {
			list.add("-r");
		}

		list.add("-radix" + radix.toString());

		if (outputFileExtension != null) {
			list.add("-s" + outputFileExtension);
		}

		if (shouldOutputSpaceBetweenKeywords) {
			list.add("-space");
		}

		if (shouldUseTabsForIndentation) {
			list.add("-t");
		}

		if (verbose) {
			list.add("-v");
		}

		if (file.isDirectory()) {
			list.add(file.getAbsolutePath() + "/*.class");
		}
		else {
			list.add(file.getAbsolutePath());
		}

		return list.toArray(new String[list.size()]);
	}

	private static String getJadPath() throws IOException {
		File jadExecutableFile =
			Application.getOSFile((Platform.CURRENT_PLATFORM == Platform.WIN_32 ||
				Platform.CURRENT_PLATFORM == Platform.WIN_64) ? "jad.exe" : "jad");

		String jadPath = jadExecutableFile.getAbsolutePath();
		return jadPath;
	}

	/**
	 * A cached check for the presence of the external JAD executable.
	 * 
	 * @return boolean if the executable, for the current platform, is present
	 */
	public static boolean isJadPresent() {
		return JADPresentHolder.JAD_PRESENT;
	}

	static class JADPresentHolder {
		static final boolean JAD_PRESENT = isJadPresent();

		static boolean isJadPresent() {
			try {
				String path = getJadPath();
				if (path != null) {
					return true;
				}
			}
			catch (IOException ioe) {
				// fall thru
			}
			return false;
		}
	}

}
