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
 * archive should upgrade to the latest version (Only relevant if opening for update)
 */
public enum Upgrade {
	YES, // will try to upgrade to the latest version if opened for update and not at latest version
	NO,	 // will not upgrade to the latest version and will fail instead if not at latest version
	ASK  // will prompt the user if the archive can be upgraded to the latest version
}
