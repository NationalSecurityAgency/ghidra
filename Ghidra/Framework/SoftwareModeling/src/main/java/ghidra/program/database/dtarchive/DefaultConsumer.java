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
package ghidra.program.database.dtarchive;

import ghidra.program.model.data.FileDataTypeManager;

/**
 * Objects used as a consumer for legacy FileDataTypeArchives where they didn't take a consumer
 * and could be closed via a close method in the {@link FileDataTypeManager}. The close method
 * can specifically look for DefaultConsumer and safely close them. This class can be removed
 * when the deprecated FileDataTypeManager interface is deleted.
 */
@Deprecated(since = "12.2", forRemoval = true)
public class DefaultConsumer {
	// marker class
}
