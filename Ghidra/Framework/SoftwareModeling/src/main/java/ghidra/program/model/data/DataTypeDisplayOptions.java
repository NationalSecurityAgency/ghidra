/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.model.data;

public interface DataTypeDisplayOptions {
	public static int MAX_LABEL_STRING_LENGTH = 32;
	public static DataTypeDisplayOptions DEFAULT = new DataTypeDisplayOptions() {
		@Override
		public boolean useAbbreviatedForm() {
			return false;
		}

		@Override
		public int getLabelStringLength() {
			return MAX_LABEL_STRING_LENGTH;
		}
	};

	public int getLabelStringLength();

	public boolean useAbbreviatedForm();
}
