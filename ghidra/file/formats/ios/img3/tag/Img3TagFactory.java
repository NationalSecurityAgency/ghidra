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
package ghidra.file.formats.ios.img3.tag;

import ghidra.app.util.bin.BinaryReader;
import ghidra.file.formats.ios.img3.AbstractImg3Tag;
import ghidra.file.formats.ios.img3.Img3Constants;
import ghidra.util.StringUtilities;

import java.io.IOException;

public final class Img3TagFactory {

	public final static AbstractImg3Tag get(BinaryReader reader) throws IOException {
		String tag = StringUtilities.toString( reader.peekNextInt() );

		if (tag == null || tag.length() == 0) {//TODO
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_BDID_MAGIC )) {
			return new BdidTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_BORD_MAGIC )) {
			return new BoardTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_CERT_MAGIC )) {
			return new CertficateTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_CHIP_PROD )) {
			return new ChipTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_DATA_MAGIC )) {
			return new DataTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_ECID_MAGIC )) {
			return new ExclusiveChipTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_KBAG_MAGIC )) {
			return new KBagTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_PROD_MAGIC )) {
			return new ProductionModeTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_SCEP_MAGIC )) {
			return new ScepTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_SDOM_MAGIC )) {
			return new SecurityDomainTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_SEPO_MAGIC )) {
			return new SecurityEpochTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_SHSH_MAGIC )) {
			return new RsaShaTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_TYPE_MAGIC )) {
			return new TypeTag( reader );
		}
		else if (tag.equals( Img3Constants.IMG3_TAG_VERS_MAGIC )) {
			return new VersionTag( reader );
		}
		return new UnknownTag( reader );
	}
}
