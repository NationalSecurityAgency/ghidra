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
package ghidra.program.model.sourcemap;

import ghidra.program.database.sourcemap.SourceFile;

/**
 * A container for a source path transformation.  No validation is performed on the inputs.
 * @param source A path (directory transform) or a String of the form SourceFileIdName + "#" + ID +
 *  "#" + SourceFile path (file transform)
 * @param sourceFile SourceFile (null for directory tranforms) 
 * @param target transformed path
 */
public record SourcePathTransformRecord(String source, SourceFile sourceFile, String target) {

	public boolean isDirectoryTransform() {
		return source.endsWith("/");
	}

}
