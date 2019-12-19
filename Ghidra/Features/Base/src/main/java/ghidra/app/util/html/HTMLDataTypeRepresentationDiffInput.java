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
package ghidra.app.util.html;

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.html.diff.DataTypeDiffInput;

public class HTMLDataTypeRepresentationDiffInput implements DataTypeDiffInput {

	private HTMLDataTypeRepresentation source;
	private List<ValidatableLine> lines;

	public HTMLDataTypeRepresentationDiffInput(HTMLDataTypeRepresentation source,
			List<ValidatableLine> lines) {
		this.source = source;
		this.lines = lines;
	}

	@Override
	public List<ValidatableLine> getLines() {
		return lines;
	}

	@Override
	public PlaceHolderLine createPlaceHolder(ValidatableLine oppositeLine) {
		return source.createPlaceHolderLine(oppositeLine);
	}

	@Override
	public String toString() {
		return source.getClass().getSimpleName() + '\n' + StringUtils.join(lines, ",\n");
	}
}
