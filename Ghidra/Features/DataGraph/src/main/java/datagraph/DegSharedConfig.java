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
package datagraph;

// Simple storage of shared data graph configuration states. If any provider changes any of these,
// then that will be the value going forward. In other words, the last one in wins.
public class DegSharedConfig {
	private boolean navigateIn = false;
	private boolean navigateOut = true;
	private boolean showPopups = true;
	private boolean useCompactFormat = true;

	public boolean isNavigateIn() {
		return navigateIn;
	}

	public void setNavigateIn(boolean navigateIn) {
		this.navigateIn = navigateIn;
	}

	public boolean isNavigateOut() {
		return navigateOut;
	}

	public void setNavigateOut(boolean navigateOut) {
		this.navigateOut = navigateOut;
	}

	public boolean isShowPopups() {
		return showPopups;
	}

	public void setShowPopups(boolean showPopups) {
		this.showPopups = showPopups;
	}

	public boolean useCompactFormat() {
		return useCompactFormat;
	}

	public void setCompactFormat(boolean useCompactFormat) {
		this.useCompactFormat = useCompactFormat;
	}

}
