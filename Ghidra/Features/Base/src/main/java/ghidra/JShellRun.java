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
package ghidra;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Stream;

import ghidra.framework.*;
import jdk.jshell.tool.JavaShellToolBuilder;

public class JShellRun implements GhidraLaunchable {
	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		if (Stream.of(args).anyMatch(a -> a.startsWith("--execution"))) {
			System.err.println("Ignoring --execution option. Overridden to local");
		}

		ArrayList<String> fullArgs = new ArrayList<>();
		fullArgs.addAll(Arrays.asList(args));

		ApplicationConfiguration configuration;
		if (fullArgs.remove("--headless")) {
			configuration = new HeadlessGhidraApplicationConfiguration();
		}
		else {
			GhidraApplicationConfiguration gac = new GhidraApplicationConfiguration();
			gac.setShowSplashScreen(false);
			configuration = gac;
		}
		Application.initializeApplication(layout, configuration);

		fullArgs.add("--execution=local");
		JavaShellToolBuilder.builder().start(fullArgs.toArray(String[]::new));
	}
}
