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
package ghidra.app.util.bin.format.macho.commands.codesignature;

/**
 * Code Signature constants
 * 
 * @see <a href="https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h">osfmk/kern/cs_blobs.h</a> 
 */
public class CodeSignatureConstants {

	public static final int CSMAGIC_REQUIREMENT = 0xfade0c00;
	public static final int CSMAGIC_REQUIREMENTS = 0xfade0c01;
	public static final int CSMAGIC_CODEDIRECTORY = 0xfade0c02;
	public static final int CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
	public static final int CSMAGIC_EMBEDDED_SIGNATURE_OLD = 0xfade0b02;
	public static final int CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
	public static final int CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xfade7172;
	public static final int CSMAGIC_DETACHED_SIGNATURE = 0xfade0cc1;
	public static final int CSMAGIC_BLOBWRAPPER = 0xfade0b01;
	public static final int CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT = 0xfade8181;
}
