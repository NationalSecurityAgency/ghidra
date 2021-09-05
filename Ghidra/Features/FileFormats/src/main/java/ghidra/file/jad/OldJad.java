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

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;

/**
 * 
 * Wrapper class for JAD, a java decompiler.
 *
 */
class OldJad {

	public File outputDirectory;
	public boolean shouldDecompileDeadCode;
	public boolean shouldOutputFieldsBeforeMethods;
	public boolean shouldInsertNewLineBeforeOpeningBrace;
	public boolean shouldOverwriteOutputFiles;
	public Radix radix = Radix.TEN;
	public String outputFileExtension;
	public boolean shouldUseTabsForIndentation;
	public boolean shouldOutputSpaceBetweenKeywords;
	public boolean verbose;
	public boolean shouldRestoreDirectoryStructure;

	OldJad() {
	}

	public File decompile(String className, File classFile, TaskMonitor monitor) throws IOException {

		int lastDotPos = className.lastIndexOf('.');
		String baseName = className.substring(0, lastDotPos);
		File javaOutputFile = new File(classFile.getParentFile(), baseName + ".java");

		Runtime runtime = Runtime.getRuntime();

		List<String> commandsList = new ArrayList<String>();

		commandsList.add(getJadPath());

		if (shouldDecompileDeadCode) {
			commandsList.add("-dead");
		}

		if (shouldOutputFieldsBeforeMethods) {
			commandsList.add("-ff");
		}

		if (!shouldInsertNewLineBeforeOpeningBrace) {
			commandsList.add("-nonlb");
		}

		if (shouldOverwriteOutputFiles) {
			commandsList.add("-o");
		}

		if (shouldRestoreDirectoryStructure) {
			commandsList.add("-r");
		}

		commandsList.add("-radix" + radix.toString());

		if (outputFileExtension != null) {
			commandsList.add("-s" + outputFileExtension);
		}

		if (shouldOutputSpaceBetweenKeywords) {
			commandsList.add("-space");
		}

		if (shouldUseTabsForIndentation) {
			commandsList.add("-t");
		}

		if (verbose) {
			commandsList.add("-v");
		}

		commandsList.add(classFile.getAbsolutePath());

		String[] commands = commandsList.toArray(new String[commandsList.size()]);

		String[] environment = new String[] {};

		File workingDirectory = classFile.getParentFile();

		Process process = runtime.exec(commands, environment, workingDirectory);
		waitForProcessToRespond(process);

		String stdinMessages = readStdinMessagesFromProcess(process, monitor);

		if (SystemUtilities.isInDevelopmentMode()) {
			if (stdinMessages != null && stdinMessages.length() > 0) {
				System.out.println(stdinMessages);
			}
		}

		String stderrMessages = readStderrMessagesFromProcess(process, monitor);

		if (SystemUtilities.isInDevelopmentMode()) {
			if (stderrMessages != null && stderrMessages.length() > 0) {
				System.out.println(stderrMessages);
			}
		}

		return javaOutputFile;
	}

	private void waitForProcessToRespond(Process process) {
		try {
			process.waitFor();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	private String getJadPath() throws FileNotFoundException {
		if (Platform.CURRENT_PLATFORM == Platform.WIN_X86_32 ||
			Platform.CURRENT_PLATFORM == Platform.WIN_X86_64) {
			File jadExecutableFile = Application.getOSFile("jad.exe");
			String jadPath = jadExecutableFile.getAbsolutePath();
			return jadPath;
		}
		File jadExecutableFile = Application.getOSFile("jad");
		String jadPath = jadExecutableFile.getAbsolutePath();
		return jadPath;
	}

	private String readStdinMessagesFromProcess(Process process, TaskMonitor monitor)
			throws IOException {
		StringBuffer buffer = new StringBuffer();
		byte[] bytes = new byte[0x1000];
		InputStream inputStream = process.getInputStream();
		while (!monitor.isCancelled()) {
			int nRead = inputStream.read(bytes);
			if (nRead == -1) {
				break;
			}
			buffer.append(new String(bytes, 0, nRead));
		}
		return buffer.toString();
	}

	private String readStderrMessagesFromProcess(Process process, TaskMonitor monitor)
			throws IOException {
		StringBuffer buffer = new StringBuffer();
		byte[] bytes = new byte[0x1000];
		InputStream processErrorStream = process.getErrorStream();
		while (!monitor.isCancelled()) {
			int nRead = processErrorStream.read(bytes);
			if (nRead == -1) {
				break;
			}
			buffer.append(new String(bytes, 0, nRead));
		}
		return buffer.toString();
	}

}
