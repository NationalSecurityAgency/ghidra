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
package generic.theme.laf;

import generic.theme.LafType;

/**
 * Generic {@link LookAndFeelManager} for lookAndFeels that do not require any special handling
 * to install or update
 */
public class GenericLookAndFeelManager extends LookAndFeelManager {

	public GenericLookAndFeelManager(LafType laf) {
		super(laf);
	}

	@Override
	protected LookAndFeelInstaller getLookAndFeelInstaller() {
		return new LookAndFeelInstaller(getLookAndFeelType());
	}

}
