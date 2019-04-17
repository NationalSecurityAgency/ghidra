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

import ghidra.app.context.NavigatableActionContext;

public interface MemorySearchService {

	/*
	 * sets up MemSearchDialog based on given bytes
	 */
	public void search(byte[] bytes, NavigatableActionContext context);

	/*
	 * sets the search value field to the masked bit string
	 */
	public void setSearchText(String maskedString);

	/*
	 * determines whether the dialog was called by a mnemonic or not
	 */
	public void setIsMnemonic(boolean isMnemonic);

}
