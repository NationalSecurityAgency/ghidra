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
package ghidra.dbg.target;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;

public interface TargetCmdLineLauncherEx extends TargetLauncher {
	String CMDLINE_ARGS_NAME = "args";

	/**
	 * The {@code args} parameter
	 */
	ParameterDescription<String> PARAMETER_CMDLINE_ARGS = ParameterDescription.create(
		String.class,
		CMDLINE_ARGS_NAME, true, "", "Command Line", "space-separated command-line arguments");

	/**
	 * A map of parameters suitable for invoking {@link #launch(List)}
	 */
	TargetParameterMap PARAMETERS = TargetMethod.makeParameters(PARAMETER_CMDLINE_ARGS);

	/**
	 * Check if the given image path contains spaces, and surround it in double quotes
	 * ({@code "}) if necessary.
	 * 
	 * <p>
	 * Without the quotes the launcher will likely confuse the spaces for separating arguments.
	 * When constructing the command-line to launch a program, this method must be used, even if
	 * the image is the only "argument."
	 * 
	 * @param imagePath the path to the image on the target platform.
	 * @return the path, possibly surrounded in quotes.
	 */
	static String quoteImagePathIfSpaces(String imagePath) {
		if (imagePath.contains(" ")) {
			return '"' + imagePath + '"';
		}
		return imagePath;
	}

	@Override
	default public TargetParameterMap getParameters() {
		return PARAMETERS;
	}

	/**
	 * Launch a target using the given arguments
	 * 
	 * <p>
	 * This is mostly applicable to user-space contexts, in which case, this usually means to
	 * launch a new process with the given arguments, where the first argument is the path to
	 * the executable image on the target host's file system.
	 * 
	 * @param args the arguments
	 * @return a future which completes when the command has been processed
	 */
	@Override
	public default CompletableFuture<Void> launch(Map<String, ?> args) {
		return launch(args);
	}
}
