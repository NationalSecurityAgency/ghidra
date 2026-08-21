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
package ghidra.framework.main.datatree;

/**
 * {@link Cuttable} associated with an element which supports cut/paste operation
 */
public interface Cuttable {

	/**
	 * Set this node to be deleted so that it can be rendered as such.
	 * @param isCut true if node will be cut and moved
	 */
	public void setIsCut(boolean isCut);

	/**
	 * {@return true if node will be cut and moved}
	 */
	public boolean isCut();

}
