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
package ghidra.file.formats.ios.img3;

public final class Img3Constants {

	/** IMG3 magic value */
	public final static String  IMG3_SIGNATURE         =  "Img3";
	/** IMG3 magic value as bytes */
	public final static byte [] IMG3_SIGNATURE_BYTES   =  { '3', 'g', 'm', 'I' };
	/** The length (in bytes) of the signature */
	public final static int IMG3_SIGNATURE_LENGTH      =  IMG3_SIGNATURE_BYTES.length;

	/** */
	public final static String IMG3_TAG_BDID_MAGIC  =  "BDID";
	/** Board to be used with */
	public final static String IMG3_TAG_BORD_MAGIC  =  "BORD";
	/** Chip to be used with; e.g. "8900" => "S5L8900" */
	public final static String IMG3_TAG_CHIP_PROD   =  "CHIP";
	/** Certificate */
	public final static String IMG3_TAG_CERT_MAGIC  =  "CERT";
	/** The code portion of the firmware, usually encrypted */
	public final static String IMG3_TAG_DATA_MAGIC  =  "DATA";
	/** Exclusive chip ID unique to every device with iPhone OS running */
	public final static String IMG3_TAG_ECID_MAGIC  =  "ECID";
	/** Contains the KEY and IV required to decrypt the GID-key */
	public final static String IMG3_TAG_KBAG_MAGIC  =  "KBAG";
	/** Production Mode */
	public final static String IMG3_TAG_PROD_MAGIC  =  "PROD";
	/** Security Domain */
	public final static String IMG3_TAG_SDOM_MAGIC  =  "SDOM";
	/** Security EPOCH */
	public final static String IMG3_TAG_SEPO_MAGIC  =  "SEPO";
	/** */
	public final static String IMG3_TAG_SCEP_MAGIC  =  "SCEP";
	/** RSA encrypted  SHA1 has of the file */
	public final static String IMG3_TAG_SHSH_MAGIC  =  "SHSH";
	/** Type information */
	public final static String IMG3_TAG_TYPE_MAGIC  =  "TYPE";
	/** iBoot version of image */
	public final static String IMG3_TAG_VERS_MAGIC  =  "VERS";

	public final static String IMG3_TYPE_LLB           = "illb";
	public final static String IMG3_TYPE_IBOOT         = "ibot";
	public final static String IMG3_TYPE_IBEC          = "ibec";
	public final static String IMG3_TYPE_IBSS          = "ibss";
	public final static String IMG3_TYPE_KERNEL        = "krnl";
	public final static String IMG3_TYPE_RAMDISK       = "rdsk";
	public final static String IMG3_TYPE_APPLE_LOGO    = "logo";
	public final static String IMG3_TYPE_RECOVERY_MODE = "recm";
}
