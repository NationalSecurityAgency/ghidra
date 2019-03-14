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
package ghidra.file.formats.ios.img2;

public final class Img2Constants {

	/** IMG2 magic value */
	public final static String IMG2_SIGNATURE  = "Img2";

	/** IMG2 magic value as bytes */
	public final static byte [] IMG2_SIGNATURE_BYTES  =  { '2', 'g', 'm', 'I' };

	/** Overall size of IMG2 header */
	public final static int IMG2_LENGTH = 0x400;

	public final static String IMAGE_TYPE_logo = "logo";//applelogo.img2
	public final static String IMAGE_TYPE_batC = "batC";//batterycharging.img2
	public final static String IMAGE_TYPE_batl = "batl";//batterylow0.img2
	public final static String IMAGE_TYPE_batL = "batL";//batterylow1.img2
	public final static String IMAGE_TYPE_dtre = "dtre";//DeviceTree.m68ap.img2
	public final static String IMAGE_TYPE_ibot = "ibot";//iBoot.m68a9.RELEASE.img2
	public final static String IMAGE_TYPE_llbz = "llbz";//LLB.m68ap.RELEASE.img2
	public final static String IMAGE_TYPE_nsvr = "nsrv";//needservice.img2
	public final static String IMAGE_TYPE_recm = "recm";//recoverymode.img2

}
