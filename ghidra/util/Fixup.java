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
package ghidra.util;

import ghidra.framework.plugintool.ServiceProvider;

public interface Fixup {

	/**
	 * Returns a description of what this Fixup.  Typically, it will either be a simple suggestion
	 * for something the user could do, or it might be a description of whate the fixup() method will
	 * attempt to do to address some issue.
	 * @return a description for this Fixup
	 */
	public String getDescription();

	/**
	 * Return true if this Fixup object can automatically perform some action to address the issue. false 
	 * if the fixup() method does nothing.
	 * @return
	 */
	public boolean canFixup();

	/**
	 * Attempts to perform some action or task to "fix" the related issue.
	 * @param provider a service provider that can provide various services.
	 * @return true if the fixup performed its intended action.
	 */
	public boolean fixup(ServiceProvider provider);
}
