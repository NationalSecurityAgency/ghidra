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
package ghidra.app.util.bin.format.pdb2.pdbreader;

/**
 * This is the base class for certain record items that get parsed from a PDB and which we would
 *  like to have toString() methods on.
 */
public abstract class AbstractParsableItem {

	/**
	 * Emits {@link String} output of this class into the provided {@link StringBuilder}.
	 * @param builder The {@link StringBuilder} into which the output is created.
	 */
	public void emit(StringBuilder builder) {
		builder.append(this.getClass().getSimpleName());
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		emit(builder);
		return builder.toString();
	}

}
