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
package ghidra.bitpatterns.gui;

import java.io.*;
import java.math.BigInteger;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;

import ghidra.bitpatterns.info.ContextRegisterFilter;
import ghidra.bitpatterns.info.PatternType;
import ghidra.util.bytesearch.DittedBitSequence;

/**
 * Objects in this class are used to display a pattern (selected by the user)
 * in the pattern clipboard
 */

public class PatternInfoRowObject {

	private PatternType type;
	private DittedBitSequence bitSequence;
	private ContextRegisterFilter cRegFilter;
	private String note;
	private Integer alignment;

	/**
	 * Represents one pattern
	 * @param type type of the pattern
	 * @param bitSequence bit sequence of the pattern
	 * @param cRegFilter context register filter constraining pattern
	 */
	public PatternInfoRowObject(PatternType type, DittedBitSequence bitSequence,
			ContextRegisterFilter cRegFilter) {
		this.type = type;
		this.bitSequence = bitSequence;
		this.cRegFilter = cRegFilter;
		alignment = null;
	}

	/**
	 * Gets the type of this pattern
	 * @return pattern type
	 */
	public PatternType getPatternType() {
		return type;
	}

	/**
	 * Gets the {@link DittedBitSequence} representing this pattern
	 * @return sequence
	 */
	public DittedBitSequence getDittedBitSequence() {
		return bitSequence;
	}

	/**
	 * Gets the {@link ContextRegisterFilter} associated with this pattern
	 * @return context register filter
	 */
	public ContextRegisterFilter getContextRegisterFilter() {
		return cRegFilter;
	}

	/**
	 * Gets the alignment associated with this pattern
	 * @return alignment
	 */
	public Integer getAlignment() {
		return alignment;
	}

	/**
	 * Sets the alignment associated with this pattern
	 * @param alignment
	 */
	public void setAlignment(Integer alignment) {
		this.alignment = alignment;
	}

	/**
	 * Gets the note associated with this pattern
	 * @return
	 */
	public String getNote() {
		return note;
	}

	/**
	 * Sets the note associated with this pattern
	 * @param note note to set
	 */
	public void setNote(String note) {
		this.note = note.trim();
	}

	//don't hash in the note
	@Override
	public int hashCode() {
		int hash = 17;
		hash = 31 * hash + type.hashCode();
		hash = 31 * hash + bitSequence.hashCode();
		hash = 31 * hash + Objects.hashCode(cRegFilter);
		hash = 31 * hash + Objects.hashCode(alignment);
		return hash;
	}

	//don't consider the note
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof PatternInfoRowObject)) {
			return false;
		}
		PatternInfoRowObject otherRow = (PatternInfoRowObject) o;
		if (!(otherRow.type.equals(type))) {
			return false;
		}
		if (!(otherRow.bitSequence.equals(bitSequence))) {
			return false;
		}
		if (!Objects.equals(otherRow.cRegFilter, cRegFilter)) {
			return false;
		}
		if (!Objects.equals(alignment, otherRow.alignment)) {
			return false;
		}
		return true;
	}

	/**
	 * Export the patterns to an XML file
	 * @param rows patterns
	 * @param xmlFile destination file
	 * @param postbits number of postbits to require
	 * @param totalbits number totalbits to require
	 * @throws IOException
	 */
	public static void exportXMLFile(List<PatternInfoRowObject> rows, File xmlFile,
			Integer postbits, Integer totalbits) throws IOException {

		try (FileWriter fWriter = new FileWriter(xmlFile);
				BufferedWriter bWriter = new BufferedWriter(fWriter)) {
			bWriter.write("<patternlist>\n");
			bWriter.write("  <patternpairs totalbits=\"");
			bWriter.write(Integer.toString(totalbits));
			bWriter.write("\" postbits=\"");
			bWriter.write(Integer.toString(postbits));
			bWriter.write("\">\n");
			bWriter.write("    <prepatterns>\n");
			for (PatternInfoRowObject row : rows) {
				if (row.getPatternType().equals(PatternType.PRE)) {
					bWriter.write("        <data>");
					bWriter.write(row.getDittedBitSequence().getHexString());
					bWriter.write("</data>\n");
				}
			}
			bWriter.write("    </prepatterns>\n");
			bWriter.write("    <postpatterns>\n");
			for (PatternInfoRowObject row : rows) {
				if (row.getPatternType().equals(PatternType.FIRST)) {
					bWriter.write("       <data>");
					bWriter.write(row.getDittedBitSequence().getHexString());
					bWriter.write("</data>\n");
				}
			}
			//find the alignment and context register constraints
			Integer alignment = null;
			ContextRegisterFilter cRegFilter = null;
			for (PatternInfoRowObject row : rows) {
				if (row.getPatternType().equals(PatternType.FIRST)) {
					alignment = row.getAlignment();
					cRegFilter = row.getContextRegisterFilter();
					break;
				}
			}
			if (alignment != null) {
				bWriter.write("       <align mark=\"0\" bits=\"");
				bWriter.write(Integer.toString(Integer.numberOfTrailingZeros(alignment)));
				bWriter.write("\"/>\n");
			}
			if (cRegFilter != null) {
				for (Entry<String, BigInteger> entry : cRegFilter.getValueMap().entrySet()) {
					String name = entry.getKey();
					String value = entry.getValue().toString();
					bWriter.write("       <setcontext name=\"");
					bWriter.write(name);
					bWriter.write("\" value=\"");
					bWriter.write(value);
					bWriter.write("\"/>\n");
				}
			}
			bWriter.write("       <funcstart/>\n");
			bWriter.write("    </postpatterns>\n");
			bWriter.write("  </patternpairs>\n");
			bWriter.write("</patternlist>\n");
		}
	}
}
