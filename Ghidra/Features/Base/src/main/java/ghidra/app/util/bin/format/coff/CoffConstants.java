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

public class CoffConstants {

	/**
	 * Max length (in bytes) of an in-place section name.
	 */
	public final static int SECTION_NAME_LENGTH         =   8;
	/**
	 * Max length (in bytes) of an in-place symbol name.
	 */
	public final static int SYMBOL_NAME_LENGTH          =   8;
	/**
	 * Length (in bytes) of a symbol data structure.
	 */
	public final static int SYMBOL_SIZEOF               =  18;
	/**
	 * Max-length (in bytes) of a file name.
	 */
	public final static int FILE_NAME_LENGTH            =  14;
	/**
	 * Number of dimensions of a symbol's auxiliary array.
	 */
	public final static int AUXILIARY_ARRAY_DIMENSION   =  4;
}
