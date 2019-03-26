/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util;

/**
 * Miscellanious address space defines for language providers.
 * Provides recommended default address space names and IDs.
 */
public interface ProcessorInfo { 
	/**
	 * The default address space in a program.
	 */
	public static final String DEFAULT_SPACE = "MEM";
	/**
	 * The code space in a program.
	 */
	public static final String CODE_SPACE = "CODE";
	/**
	 * The internal memory space in a program.
	 */
	public static final String INTMEM_SPACE = "INTMEM";
	/**
	 * The bit space in a program.
	 */
	public static final String BIT_SPACE = "BITS";
	/**
	 * The external memory space in a program.
	 */
	public static final String EXTMEM_SPACE = "EXTMEM";
	/**
	 * The Special function registers space in a program
	 */
	public static final String SFR_SPACE = "SFR";
	
	/**
	 * ID for the CODE_SPACE.
	 */
	public static final int CODE_SPACE_ID = 0;
	/**
	 * ID for the INTMEM_SPACE.
	 */
	public static final int INTMEM_SPACE_ID = 3;
	/**
	 * ID for the SFR_SPACE.
	 */
	public static final int SFR_SPACE_ID = 4;
	/**
	 * ID for the EXTMEM_SPACE.
	 */
	public static final int EXTMEM_SPACE_ID = 8;
}
