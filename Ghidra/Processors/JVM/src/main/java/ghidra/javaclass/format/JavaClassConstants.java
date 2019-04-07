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
package ghidra.javaclass.format;

public final class JavaClassConstants {

	public final static int MAGIC = 0xcafebabe;

	public final static byte[] MAGIC_BYTES = { (byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe };

	// Table 6.1. Array type codes

	public static final byte T_BOOLEAN = 4;
	public static final byte T_CHAR = 5;
	public static final byte T_FLOAT = 6;
	public static final byte T_DOUBLE = 7;
	public static final byte T_BYTE = 8;
	public static final byte T_SHORT = 9;
	public static final byte T_INT = 10;
	public static final byte T_LONG = 11;

	public static final String OPERAND_PLACEHOLDER = "&&&";

}
