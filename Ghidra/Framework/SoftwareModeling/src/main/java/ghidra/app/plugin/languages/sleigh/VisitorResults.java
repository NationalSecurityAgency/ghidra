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
package ghidra.app.plugin.languages.sleigh;

/**
 * Some constants for controlling traversal
 * 
 * A callback ({@code visit()}) can return one of these constants to control whether or not
 * traversal continues. {@code traverse()} methods will return a value to indicate how traversal
 * terminated.
 */
public interface VisitorResults {
	/**
	 * Continue
	 * 
	 * From {@code visit()}: continue traversal as usual.
	 * This value is never returned by {@code traverse()}.
	 */
	public static final int CONTINUE = 0;

	/**
	 * Finish(ed)
	 * 
	 * From {@code visit()}: terminate traversal with a successful result.
	 * From {@code traverse()}: traversal terminated successfully. Either a call to {@code visit()}
	 * returned {@link #FINISHED}, or all calls to {@code visit()} returned {@link #CONTINUE}.
	 */
	public static final int FINISHED = 1;

	/**
	 * Terminate(d)
	 * 
	 * From {@code visit()}: terminate traversal with an unsuccessful result.
	 * From {@code traverse()}: traversal terminated unsuccessful. Either a call to {@code visit()}
	 * returned {@link #TERMINATE}, or there was an error during traversal.
	 */
	public static final int TERMINATE = 2;
}
