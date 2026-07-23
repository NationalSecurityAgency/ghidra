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
package ghidra.app.plugin.core.assembler.completion;

import generic.theme.GThemeDefaults.Colors;

/**
 * Represents the description of an error encountered during parsing or assembling
 * 
 * <p>
 * <b>NOTE:</b> not used until error descriptions improve
 */
public class ErrorAssemblyCompletion extends AssemblyCompletion {
	private String text;

	public ErrorAssemblyCompletion(String text, String desc) {
		super(text, desc, Colors.ERROR, 1);
		this.text = text;
	}

	@Override
	public String getText() {
		return text;
	}
}
