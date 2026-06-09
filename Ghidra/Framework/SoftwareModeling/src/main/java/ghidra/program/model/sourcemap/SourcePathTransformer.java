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

import java.util.List;

import ghidra.program.database.sourcemap.SourceFile;

/**
 * SourcePathTransformers are used to transform {@link SourceFile} paths.  The intended use is
 * to transform the path of a {@link SourceFile} in a programs's {@link SourceFileManager}
 * before sending the path to an IDE.<br>
 * <p>
 * There are two types of transformations: file and directory.  File transforms
 * map a particular {@link SourceFile} to an absolute file path. Directory transforms
 * transform an initial segment of a path.  For example, the directory transforms
 * "/c:/users/" -> "/src/test/" sends "/c:/users/dir/file1.c" to "/src/test/dir/file1.c" 
 */
public interface SourcePathTransformer {

	/**
	 * Adds a new file transform.  Any existing file transform for {@code sourceFile} is 
	 * overwritten.  {@code path} must be a valid, normalized file path (with forward slashes).
	 * @param sourceFile source file (can't be null). 
	 * @param path new path
	 */
	public void addFileTransform(SourceFile sourceFile, String path);

	/**
	 * Removes any file transform for {@code sourceFile}.
	 * @param sourceFile source file 
	 */
	public void removeFileTransform(SourceFile sourceFile);

	/**
	 * Adds a new directory transform.  Any existing directory transform for {@code sourceDir}
	 * is overwritten.  {@code sourceDir} and {@code targetDir} must be valid, normalized
	 * directory paths (with forward slashes).
	 * @param sourceDir source directory
	 * @param targetDir target directory
	 */
	public void addDirectoryTransform(String sourceDir, String targetDir);

	/**
	 * Removes any directory transform associated with {@code sourceDir}
	 * @param sourceDir source directory
	 */
	public void removeDirectoryTransform(String sourceDir);

	/**
	 * Returns the transformed path for {@code sourceFile}.  The transformed path is determined as
	 * follows:<br>
	 * - If there is a file transform for {@code sourceFile}, the file transform is applied.<br>
	 * - Otherwise, the most specific directory transform (i.e., longest source directory string) 
	 *   is applied.<br>
	 * - If no directory transform applies, the value of {@code useExistingAsDefault} determines
	 * whether the path of {@code sourceFile} or {@code null} is returned.
	 * 
	 * @param sourceFile source file to transform
	 * @param useExistingAsDefault whether to return sourceFile's path if no transform applies
	 * @return transformed path or null
	 */
	public String getTransformedPath(SourceFile sourceFile, boolean useExistingAsDefault);

	/**
	 * Returns a list of all {@link SourcePathTransformRecord}s 
	 * @return transform records
	 */
	public List<SourcePathTransformRecord> getTransformRecords();

}
