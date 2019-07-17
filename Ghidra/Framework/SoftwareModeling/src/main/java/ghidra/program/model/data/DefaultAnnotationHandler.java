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

public class DefaultAnnotationHandler implements AnnotationHandler {
	private static final String[] FILE_EXTENSIONS = new String[] { "c", "h", "cpp" };

	public String getPrefix(Enum e, String member) {
		return "";
	}

	public String getSuffix(Enum e, String member) {
		return "";
	}

	public String getPrefix(Composite c, DataTypeComponent dtc) {
		return "";
	}

	public String getSuffix(Composite c, DataTypeComponent dtc) {
		return "";
	}

	public String getDescription() {
		return "Default C Annotations";
	}

	public String getLanguageName() {
		return "C/C++";
	}

	public String[] getFileExtensions() {
		return FILE_EXTENSIONS;
	}

	@Override
	public String toString() {
		return getLanguageName();
	}
}
