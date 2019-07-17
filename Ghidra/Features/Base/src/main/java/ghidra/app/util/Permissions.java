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
package ghidra.app.util;

public class Permissions {
	public final static Permissions ALL = new Permissions(true, true, true);

	public final static Permissions READ_ONLY = new Permissions(true, false, false);

	public final static Permissions READ_EXECUTE = new Permissions(true, false, true);

	public final boolean read;
	public final boolean write;
	public final boolean execute;

	public Permissions(boolean read, boolean write, boolean execute) {
		this.read = read;
		this.write = write;
		this.execute = execute;
	}
}
