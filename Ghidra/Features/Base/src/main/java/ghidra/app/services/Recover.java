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
package ghidra.app.services;

/**
 * Enum for the DataTypeArchiveService to specify that when opening a ProjectDataTypeArchive if the
 * archive should recover any unsaved changes from a crashed session.
 */
public enum Recover {
	YES, 	// The open archive operation will automatically recover any crash data
	NO, 	// The open archive operation will ignore any recovery crash data
	ASK		// The open archive operation will prompt the user if recovery crash data exists
}
