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
package ghidra.app.util.html.diff;


public class DataTypeDiff {

	private DiffLines leftLines;
	private DiffLines rightLines;

	DataTypeDiff(DiffLines leftLines, DiffLines rightLines) {
		this.leftLines = leftLines;
		this.rightLines = rightLines;
	}

	public DiffLines getLeftLines() {
		return leftLines;
	}

	public DiffLines getRightLines() {
		return rightLines;
	}
}
