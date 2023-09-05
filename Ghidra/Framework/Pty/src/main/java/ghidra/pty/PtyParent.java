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
package ghidra.pty;

/**
 * The parent (UNIX "master") end of a pseudo-terminal
 */
public interface PtyParent extends PtyEndpoint {
	/**
	 * Resize the terminal window to the given width and height, in characters
	 * 
	 * @param cols the width in characters
	 * @param rows the height in characters
	 */
	void setWindowSize(short cols, short rows);
}
