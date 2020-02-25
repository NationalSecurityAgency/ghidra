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
package ghidra.app.util.demangler;

// TODO better name
public interface Demangled {

	public String getName();

	/**
	 * Returns the namespace containing this demangled object
	 * @return the namespace containing this demangled object
	 */
	public Demangled getNamespace();

	public void setNamespace(Demangled ns);

	public String toNamespaceString();

	// TODO doc difference
	public String toNamespaceName();

	/**
	 * Returns the original mangled string
	 * @return the string
	 */
	public String getMangledString();

	public void setMangledString(String mangled);
}
