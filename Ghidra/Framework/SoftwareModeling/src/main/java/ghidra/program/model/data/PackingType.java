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
package ghidra.program.model.data;

/**
 * <code>PackingType</code> specifies the pack setting which applies to a composite data type.
 * This can be DISABLED, DEFAULT, EXPLICIT.
 */
public enum PackingType {
	/**
	 * <B>DISABLED</B> - indicates that automatic component placement should not be performed, with 
	 * components placed at specified offsets and <code>undefined</code> components used to
	 * reflects padding/unused bytes.  This mode is commonly used when reverse-engineering a
	 * composite since a complete and accurate definition may not be known.
	 */
	DISABLED, 
	/**
	 * <B>DEFAULT</B> - indicates that components should be placed automatically based upon
	 * their alignment.  This is intended to reflect the default behavior of a compiler
	 * when a complete definition of a composite is known as well as the alignment of each 
	 * component.
	 */
	DEFAULT,
	/**
	 * <B>EXPLICIT</B> - indicates an explicit pack value has been specified and that components 
	 * should be placed automatically based upon their alignment, not to exceed the pack value. 
	 */
	EXPLICIT;
}
