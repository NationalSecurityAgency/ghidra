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
package ghidra.file.formats.ios.png;

public class CrushedPNGConstants {

	public final static byte[] SIGNATURE_BYTES = { (byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a,
		0x0a };

	public final static byte[] INSERTED_IOS_CHUNK = { 0x43, 0x67, 0x42, 0x49 };
	public final static byte[] IHDR_CHUNK = { 0x49, 0x48, 0x44, 0x52 };
	public final static byte[] IDAT_CHUNK = { 0x49, 0x44, 0x41, 0x54 };
	public final static byte[] IEND_CHUNK = { 0x49, 0x45, 0x4e, 0x44 };

	public final static int[] STARTING_ROW = { 0, 0, 4, 0, 2, 0, 1 };
	public final static int[] STARTING_COL = { 0, 4, 0, 2, 0, 1, 0 };
	public final static int[] ROW_INCREMENT = { 8, 8, 8, 4, 4, 2, 2 };
	public final static int[] COL_INCREMENT = { 8, 8, 4, 4, 2, 2, 1 };

	public final static int IHDR_CHUNK_DATA_SIZE = 13;
	public final static int GENERIC_CHUNK_SIZE = 12;
	public final static int INITIAL_REPACK_SIZE = 0x10000;

	public final static String IEND_STRING = "IEND";
	public final static String IHDR_STRING = "IHDR";

	public final static int ADAM7_INTERLACE = 1;
	public final static int INTERLACE_NONE = 0;
}
