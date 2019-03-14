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
package ghidra.app.util.bin.format.coff;

public final class CoffSymbolSectionNumber {
	/** special symbolic debugging symbol */
	public final static short N_DEBUG     = -2;
	/** absolute symbols */
	public final static short N_ABS       = -1;
	/** undefined external symbol */
	public final static short N_UNDEf     =  0;
	/** .text section symbol */
	public final static short N_TEXT      =  1;
	/** .data section symbol */
	public final static short N_DATA      =  2;
	/** .bss section symbol */
	public final static short N_BSS       =  3;

	/*
	 * NOTE:
	 * Section number values 4 -> 32767 are 
	 * reserved for the user defined named
	 * sections in the order in which
	 * each section is defined. 
	 */
}
