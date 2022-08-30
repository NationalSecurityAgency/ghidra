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
package ghidra.framework.model;

import java.io.IOException;

/**
 * {@code LinkedDomainFile} corresponds to a {@link DomainFile} contained within a
 * {@link LinkedDomainFolder}.
 */
public interface LinkedDomainFile extends DomainFile {

	/**
	 * Get the real domain file which corresponds to this file contained within a linked-folder.
	 * @return domain file
	 * @throws IOException if IO error occurs or file not found
	 */
	public DomainFile getLinkedFile() throws IOException;

}
