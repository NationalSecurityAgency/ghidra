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
package ghidra.app.decompiler;

import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.decompiler.component.margin.DecompilerMarginProvider;

/**
 * A service that allows clients to add custom margins in the Decompiler UI.
 */
public interface DecompilerMarginService {
	/**
	 * Add a margin to the Decompiler's primary window
	 * 
	 * @param provider the margin provider
	 */
	void addMarginProvider(DecompilerMarginProvider provider);

	/**
	 * Remove a margin from the Decompiler's primary window
	 * 
	 * @param provider the margin provider
	 */
	void removeMarginProvider(DecompilerMarginProvider provider);

	/**
	 * Get the panel associated with this margin
	 * 
	 * @return the panel
	 */
	DecompilerPanel getDecompilerPanel();
}
