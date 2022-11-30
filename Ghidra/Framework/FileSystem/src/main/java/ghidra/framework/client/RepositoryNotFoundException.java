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
package ghidra.framework.client;

import java.io.IOException;

/**
 * {@code RepositoryNotFoundException} thrown when a failed connection occurs to a
 * non-existing repository.  A valid server connection is required to make this 
 * determination.
 */
public class RepositoryNotFoundException extends IOException {

	public RepositoryNotFoundException(String msg) {
		super(msg);
	}

}
