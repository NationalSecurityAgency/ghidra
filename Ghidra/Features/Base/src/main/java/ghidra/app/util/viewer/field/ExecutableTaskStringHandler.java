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
package ghidra.app.util.viewer.field;

import java.io.*;
import java.util.*;

import docking.widgets.fieldpanel.field.AttributedString;
import ghidra.app.nav.Navigatable;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class ExecutableTaskStringHandler implements AnnotatedStringHandler {
	private static final String INVALID_SYMBOL_TEXT =
		"@execute annotation must have an " + "executable name";
	private static final String[] SUPPORTED_ANNOTATIONS = { "execute" };

	@Override
	public AttributedString createAnnotatedString(AttributedString prototypeString, String[] text,
			Program program) throws AnnotationException {
		if (text.length <= 1) {
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		String displayText = getDisplayText(text);
		if (displayText == null) {
			// some kind of error
			throw new AnnotationException(INVALID_SYMBOL_TEXT);
		}

		return new AttributedString(displayText, prototypeString.getColor(0),
			prototypeString.getFontMetrics(0), true, prototypeString.getColor(0));
	}

	private String getDisplayText(String[] text) {
		//
		// We currently support two modes of: 3 parameters or 1. The user can leave off the 
		// executable's parameter and display string OR they can have all three.  
		// 
		if (text.length == 4) {
			return text[3]; // 4 items means they have display text
		}
		else if (text.length != 2) {
			throw new AnnotationException(
				"Invalid number of inputs - " + (text.length - 1) + " found - 1 or 3 required");
		}

		// otherwise, no display text, just use the executable name
		String programInfo = text[1];
		return getDisplayTextForFilePathOrName(programInfo);
	}

	private String getDisplayTextForFilePathOrName(String fileString) {
		File file = new File(fileString);
		if (file.isAbsolute() && file.exists()) {
			return file.getName();
		}
		return fileString;
	}

	@Override
	public String getDisplayString() {
		return "Execute";
	}

	@Override
	public String getPrototypeString() {
		return "{@execute \"executable_path_and_name\" \"arg1 arg2\" \"Display Text\"}";
	}

	@Override
	public String[] getSupportedAnnotations() {
		return SUPPORTED_ANNOTATIONS;
	}

	@Override
	public boolean handleMouseClick(String[] annotationParts, Navigatable sourceNavigatable,
			ServiceProvider serviceProvider) {

		String executableName = annotationParts[1];

		List<String> command = new ArrayList<>();
		command.add(executableName);

		if (annotationParts.length > 2) {
			String commandParameterString = annotationParts[2];
			StringTokenizer tokenizer = new StringTokenizer(commandParameterString, " ");
			while (tokenizer.hasMoreTokens()) {
				command.add(tokenizer.nextToken());
			}
		}

		new ProcessThread(command).start();

		return true;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class ProcessThread extends Thread {

		private final List<String> command;

		ProcessThread(List<String> command) {
			super("Process Runner - " + command.get(0));
			this.command = command;
		}

		@Override
		public void run() {
			ProcessBuilder processBuilder = new ProcessBuilder(command);
			processBuilder = processBuilder.redirectErrorStream(true);

			IOThread ioThread = null;
			StringBuilder buffer = new StringBuilder();
			int exitValue = 1;
			InputStream inputStream = null;
			Process process = null;
			String executableName = command.get(0);
			try {
				Msg.info(this, "Launching process: " + executableName);
				process = processBuilder.start();
				inputStream = process.getInputStream();
				ioThread = new IOThread(buffer, inputStream);
				ioThread.start();
				exitValue = process.waitFor();
				ioThread.join();
				inputStream.close();
			}
			catch (Exception e) {
				Msg.showError(this, null, "Error Launching Executable",
					"Unexpected exception trying to launch process: " + executableName, e);

			}
			finally {
				if (inputStream != null) {
					try {
						inputStream.close();
					}
					catch (IOException e) {
					}
				}
			}

			if (exitValue != 0) {
				Msg.warn(this, "Process \"" + executableName + "\" exited abnormally with value: " +
					exitValue);
			}
		}
	}

	private static class IOThread extends Thread {
		private BufferedReader shellOutput;
		private StringBuilder buffer;

		IOThread(StringBuilder buffer, InputStream input) {
			super("IO Thread - Executable Annotation Task");
			this.buffer = buffer;
			shellOutput = new BufferedReader(new InputStreamReader(input));
		}

		@Override
		public void run() {
			String line = null;
			try {
				while ((line = shellOutput.readLine()) != null) {
					buffer.append(line).append('\n');
				}
			}
			catch (Exception e) {
				e.printStackTrace();
				buffer = null;
			}
		}

		String getIOData() {
			if (buffer == null) {
				return null;
			}
			return buffer.toString();
		}
	}
}
