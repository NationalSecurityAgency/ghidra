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

/**
 * Something intended to be launched by the {@link GhidraLauncher}.
 */
public interface GhidraLaunchable {

	/**
	 * Launches the launchable.
	 * 
	 * @param layout The application layout to use for the launch.
	 * @param args The arguments passed through by the {@link GhidraLauncher}.
	 * @throws Exception if there was a problem with the launch.
	 */
	public void launch(GhidraApplicationLayout layout, String[] args) throws Exception;
}
