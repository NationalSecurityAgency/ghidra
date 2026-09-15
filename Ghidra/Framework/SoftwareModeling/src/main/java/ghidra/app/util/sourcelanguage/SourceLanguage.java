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
package ghidra.app.util.sourcelanguage;

import java.io.IOException;

import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * An {@link ExtensionPoint} to dynamically support source language-specific features
 */
public interface SourceLanguage extends ExtensionPoint {

	/**
	 * {@return the {@link SourceLanguageID ID} of the source language}
	 */
	public SourceLanguageID getID();

	/**
	 * {@return true if the source language exists in the given {@link Program}; otherwise false}
	 * 
	 * @param program The {@link Program}
	 * @param monitor The {@link TaskMonitor}
	 * @throws IOException if an IO-related error occurred
	 * @throws CancelledException if the user cancelled the operation
	 */
	public boolean existsIn(Program program, TaskMonitor monitor)
			throws IOException, CancelledException;
}
