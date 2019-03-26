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
package docking.widgets.filter;

public class ContainsTextFilterFactory implements TextFilterFactory {
	private boolean caseSensitive;
	private boolean allowGlobbing;

	public ContainsTextFilterFactory(boolean caseSensitive, boolean allowGlobbing) {
		this.caseSensitive = caseSensitive;
		this.allowGlobbing = allowGlobbing;
	}

	@Override
	public TextFilter getTextFilter(String text) {
		if ((text == null) || (text.length() == 0)) {
			return null;
		}

		return new ContainsTextFilter(text, caseSensitive, allowGlobbing);
	}
}
