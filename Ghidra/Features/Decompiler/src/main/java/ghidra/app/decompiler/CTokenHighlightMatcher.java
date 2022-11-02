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

import java.awt.Color;

/**
 * The interface that clients must define to create a {@link DecompilerHighlighter}
 * 
 * <p>Every function decompiled will trigger this matcher to get called.  The order of method
 * calls is: {@link #start(ClangNode)}, repeated calls to {@link #getTokenHighlight(ClangToken)}
 * and then {@link #end()}.
 * 
 * @see DecompilerHighlightService
 */
public interface CTokenHighlightMatcher {
	public default void start(ClangNode root) {
		// stub; provided for clients that may wish to work from the root
	}

	public default void end() {
		// stub; provided for clients that may wish to perform cleanup when highlighting is finished
	}

	/**
	 * The basic method clients must implement to determine if a token should be highlighted.
	 * Returning a non-null Color will trigger the given token to be highlighted.
	 * @param token the token
	 * @return the highlight color or null
	 */
	public Color getTokenHighlight(ClangToken token);
}
