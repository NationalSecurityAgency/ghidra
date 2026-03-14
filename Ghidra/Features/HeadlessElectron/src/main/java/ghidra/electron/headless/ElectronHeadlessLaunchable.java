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
package ghidra.electron.headless;

import java.nio.file.Path;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;

public class ElectronHeadlessLaunchable implements GhidraLaunchable {

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
		Config config = Config.fromArgs(args);

		System.setProperty("java.awt.headless", "true");

		ElectronHeadlessServer server =
			new ElectronHeadlessServer(config.port, config.dataDir, config.repoRoot);
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			try {
				server.stop();
			}
			catch (Exception ignored) {
				// Best effort shutdown for launcher-triggered termination.
			}
		}, "headless-electron-shutdown"));

		server.start();
	}

	private record Config(int port, Path dataDir, Path repoRoot) {
		static Config fromArgs(String[] args) {
			String portValue = valueAt(args, 0, "GHIDRA_ELECTRON_PORT", "8089");
			String dataDirValue =
				valueAt(args, 1, "GHIDRA_ELECTRON_DATA_DIR", ".headless-electron-data");
			String repoRootValue = valueAt(args, 2, "GHIDRA_REPO", ".");
			return new Config(Integer.parseInt(portValue), Path.of(dataDirValue).toAbsolutePath(),
				Path.of(repoRootValue).toAbsolutePath());
		}

		private static String valueAt(String[] args, int index, String envName, String fallback) {
			if (args != null && args.length > index && args[index] != null &&
				!args[index].isBlank()) {
				return args[index];
			}
			String envValue = System.getenv(envName);
			if (envValue != null && !envValue.isBlank()) {
				return envValue;
			}
			return fallback;
		}
	}
}
