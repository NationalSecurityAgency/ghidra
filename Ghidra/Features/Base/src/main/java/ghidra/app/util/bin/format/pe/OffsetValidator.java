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
package ghidra.app.util.bin.format.pe;

/**
 * Provides methods for validating pointers and relative virtual addresses (RVA) in a PE file
 */
public interface OffsetValidator {

	/**
	 * {@return whether or not the specified pointer is contained within the PE file}
	 * 
	 * @param ptr the pointer value to check
	 */
	public boolean checkPointer(long ptr);

	/**
	 * {@return whether or not the specified RVA value is contained within the PE image}
	 * 
	 * @param rva the RVA to check
	 */
	public boolean checkRVA(long rva);

	/**
	 * {@return the PE's file alignment, or 0 if unknown/unused}
	 */
	public int getFileAlignment();

	/**
	 * {@return the PE's sectionAlignment, or 0 if unknown/unused}
	 */
	public int getSectionAlignment();
}
