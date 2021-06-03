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
 * <code>AlignmentType</code> specifies the type of alignment which applies to a composite data type.
 * This can be DEFAULT, MACHINE, EXPLICIT.  For packed composites, the length of the composite
 * will be padded to force the length to a multiple of the computed alignment.
 */
public enum AlignmentType {
	/**
	 * <B>DEFAULT</B> - this data type's alignment is computed based upon its current pack setting
	 * and data organization rules.  If packing is disabled the computed alignment will be 1.
	 */
	DEFAULT, 
	/**
	 * <B>MACHINE</B> - this data type's alignment will be a multiple of the machine alignment
	 * specified by the data organization.  In general, and for all non-packed composites, the 
	 * computed alignment will match the machine alignment if this setting is used.
	 */
	MACHINE, 
	/**
	 * <B>MACHINE</B> - this data type's alignment will be a multiple of the explicit alignment
	 * value specified for the datatype.  For all non-packed composites, the 
	 * computed alignment will match the machine alignment if this setting is used.
	 */
	EXPLICIT;
}
