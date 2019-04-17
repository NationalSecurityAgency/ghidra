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
package ghidra.app.util.bin.format.xcoff;

public final class XCoffFileHeaderMagic {

	/** XCOFF32 */
	public final static short MAGIC_XCOFF32      =  0x01df;
	/** XCOFF64 - discontinued AIX */
	public final static short MAGIC_XCOFF64_OLD  =  0x01ef;
	/** XCOFF64 */
	public final static short MAGIC_XCOFF64      =  0x01f7;

	public final static boolean isMatch(short magic) {
		return magic == MAGIC_XCOFF32 ||
               magic == MAGIC_XCOFF64_OLD ||
               magic == MAGIC_XCOFF64;
	}

	public final static boolean is32bit(XCoffFileHeader header) {
		return header.getMagic() == MAGIC_XCOFF32;
	}

	public final static boolean is64bit(XCoffFileHeader header) {
		return header.getMagic() == MAGIC_XCOFF64_OLD || header.getMagic() == MAGIC_XCOFF64;
	}
}
