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
package ghidra.app.util.bin.format.elf.info;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.elf.info.GnuBuildAttribute.AddressPair;
import ghidra.app.util.bin.format.elf.info.GnuBuildAttribute.AttributeType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Represents a sequence of {@link GnuBuildAttribute} elements, typically found in the
 * ".gnu.build.attributes" section.
 */
public class GnuBuildAttributes implements ElfInfoItem {
	public static final String SECTION_NAME = ".gnu.build.attributes";

	/**
	 * Reads a sequence of {@link GnuBuildAttribute} elements and returns them as a 
	 * {@link GnuBuildAttributes} instance.
	 * 
	 * @param reader {@link BinaryReader}
	 * @param program {@link Program}
	 * @return {@link GnuBuildAttributes}
	 */
	public static GnuBuildAttributes read(BinaryReader reader, Program program) {
		List<AttributeWithOffset> results = new ArrayList<>();
		while (reader.hasNext()) {
			long offset = reader.getPointerIndex();
			try {
				GnuBuildAttribute gba = reader.readNext(GnuBuildAttribute::read);
				results.add(new AttributeWithOffset(offset, gba));
			}
			catch (IOException e) {
				Msg.error(GnuBuildAttribute.class,
					"Failed to read GnuBuildAttributes at %d".formatted(offset));
				break;
			}
		}
		return new GnuBuildAttributes(results);
	}

	public record AttributeWithOffset(long offset, GnuBuildAttribute attr) {}

	private List<AttributeWithOffset> items;

	public GnuBuildAttributes(List<AttributeWithOffset> items) {
		this.items = items;
	}

	@Override
	public void markupProgram(Program program, Address address) {
		List<GnuBuildAttribute> subList = new ArrayList<>();
		AttributeType prevAttrType = null;
		AddressPair prevAddrs = null;

		// group sequential attributes together until a attribute is encountered that specifies
		// an address, or specifies a new type of attribute (open vs func)
		for (AttributeWithOffset item : items) {
			GnuBuildAttribute attr = item.attr;
			attr.markupProgram(program, address.add(item.offset));

			AddressPair addresses = attr.getRange(program);
			if ((addresses != null && prevAddrs != null && !prevAddrs.equals(addresses)) ||
				attr.getAttributeType() != prevAttrType) {
				markupRange(subList, program);
				subList.clear();
				prevAddrs = addresses;
			}

			prevAttrType = attr.getAttributeType();
			subList.add(attr);
		}
		markupRange(subList, program);
	}

	private void markupRange(List<GnuBuildAttribute> attrs, Program program) {
		if (attrs.isEmpty()) {
			return;
		}
		GnuBuildAttribute first = attrs.getFirst();
		AddressPair range = first.getRange(program);
		if (range == null) {
			return;
		}
		StringBuilder sb = new StringBuilder();
		for (GnuBuildAttribute attr : attrs) {
			if (!sb.isEmpty()) {
				sb.append(", ");
			}
			sb.append(attr.getDescription(program));
		}
		GnuBuildAttribute.appendComment(program, range.first(), CommentType.EOL, "",
			"start gnu build attribs(%s) %s\n%s"
					.formatted(first.getAttributeType().getDescription(), range, sb),
			"\n");
		GnuBuildAttribute.appendComment(program, range.second(), CommentType.EOL, "",
			"end gnu build attribs(%s) %s\n%s".formatted(first.getAttributeType().getDescription(),
				range, sb),
			"\n");
	}

}
