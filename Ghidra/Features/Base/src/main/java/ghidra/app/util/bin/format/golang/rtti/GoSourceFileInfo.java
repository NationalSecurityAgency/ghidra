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
package ghidra.app.util.bin.format.golang.rtti;

/**
 * Represents a golang source file and line number tuple.
 * 
 * @param fileName source filename
 * @param lineNum  source line number
 */
public record GoSourceFileInfo(String fileName, int lineNum) {

	public GoSourceFileInfo(String fileName, int lineNum) {
		this.fileName = fileName;
		this.lineNum = lineNum;
	}

	public String getFileName() {
		return fileName;
	}

	public int getLineNum() {
		return lineNum;
	}

	/**
	 * Returns the source location info as a string formatted as "filename:linenum"
	 *
	 * @return "filename:linenum"
	 */
	public String getDescription() {
		return "%s:%d".formatted(fileName, lineNum);
	}

	/**
	 * Returns the source location info as a string formatted as "File: filename Line: linenum"
	 *
	 * @return "File: filename Line: linenum"
	 */
	public String getVerboseDescription() {
		return "File: %s Line: %d".formatted(fileName, lineNum);
	}

}
