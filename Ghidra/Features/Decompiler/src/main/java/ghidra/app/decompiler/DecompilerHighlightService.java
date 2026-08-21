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

import ghidra.program.model.listing.Function;

/**
 * A service that allows clients to create highlights in the form of background colors for
 * {@link ClangToken}s in the Decompiler UI.
 * 
 * <p>Note: highlights apply to a full token and not strings of text.  To highlight a token, you
 * create an instance of the {@link CTokenHighlightMatcher} to pass to one of the
 * {@link #createHighlighter(String, CTokenHighlightMatcher)} methods of this interface.
 * 
 * <p>There is no limit to the number of highlighters that may be installed.  If multiple
 * highlights overlap, then their colors will be blended.  The number of color blends may be limited
 * for performance reasons.
 */
public interface DecompilerHighlightService {

	/**
	 * Creates a highlighter that will use the given matcher to create highlights as functions
	 * get decompiled.  The highlighter created will be applied to every decompiled function.  
	 * 
	 * @param tm the matcher
	 * @return the new highlighter
	 */
	public default DecompilerHighlighter createHighlighter(CTokenHighlightMatcher tm) {
		return createHighlighter((Function) null, tm);
	}

	/**
	 * Creates a highlighter that will use the given matcher to create highlights as functions
	 * get decompiled.  The highlighter created will only be applied to the given function.
	 * 
	 * @param function the function to which the highlighter will be applied
	 * @param tm the matcher
	 * @return the new highlighter
	 * @see #createHighlighter(CTokenHighlightMatcher) for global highlights
	 */
	public DecompilerHighlighter createHighlighter(Function function, CTokenHighlightMatcher tm);

	/**
	 * A version of {@link #createHighlighter(String, CTokenHighlightMatcher)} that allows clients
	 * to specify an ID.  This ID will be used to ensure that any existing highlighters with that
	 * ID will be removed before creating a new highlighter.  The highlighter created will be 
	 * applied to every decompiled function.  
	 * 
	 * <p>This method is convenient for scripts, since a script cannot hold on to any created
	 * highlighters between repeated script executions.   A good value for script writers to use
	 * is the name of their script class.
	 * 
	 * @param id the ID
	 * @param tm the matcher
	 * @return the new highlighter
	 */
	public default DecompilerHighlighter createHighlighter(String id, CTokenHighlightMatcher tm) {
		return createHighlighter(id, null, tm);
	}

	/**
	 * A version of {@link #createHighlighter(String, CTokenHighlightMatcher)} that allows clients
	 * to specify an ID.  This ID will be used to ensure that any existing highlighters with that
	 * ID will be removed before creating a new highlighter.  The highlighter created will only be 
	 * applied to the given function.  
	 * 
	 * <p>This method is convenient for scripts, since a script cannot hold on to any created
	 * highlighters between repeated script executions.   A good value for script writers to use
	 * is the name of their script class.
	 * 
	 * @param id the ID
	 * @param function the function to which the highlighter will be applied
	 * @param tm the matcher
	 * @return the new highlighter
	 */
	public DecompilerHighlighter createHighlighter(String id, Function function,
			CTokenHighlightMatcher tm);
}
