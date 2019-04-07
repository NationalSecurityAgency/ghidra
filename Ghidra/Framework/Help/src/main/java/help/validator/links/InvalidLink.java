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
package help.validator.links;

import java.nio.file.Path;

public interface InvalidLink extends Comparable<InvalidLink> {

	@Override
	public int compareTo(InvalidLink other);

	@Override
	public String toString();

	@Override
	public int hashCode();

	@Override
	public boolean equals(Object obj);

	public Path getSourceFile();

	public int getLineNumber();

	public int identityHashCode();
}
