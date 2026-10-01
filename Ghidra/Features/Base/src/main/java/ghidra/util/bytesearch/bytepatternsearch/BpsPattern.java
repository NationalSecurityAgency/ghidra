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
package ghidra.util.bytesearch.bytepatternsearch;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * This class represents a byte pattern in support of the {@link BpsXmlParser} of the Byte Pattern
 * Search capability within Ghidra.
 * <P>
 * The design of the XML Parser and its supporting classes can be found in {@link BpsXmlParser}.
 * <P>
 * The design of the Byte pattern Searcher and its supporting sub-capabilities and classes can be
 * found in the "Search For Byte Patterns" page in the help viewer.
 * <P>
 * This class represents a byte pattern object which is populated by {@link BpsXmlParser}. This
 * object wraps a search byte array (inside a {@link ByteBuffer}), its parent {@link BpsSearchItem},
 * and its parsed XML tag name for use downstream.
 * 
 * <h4>Object Variables</h4>
 * <ul>
 * <li><strong>name</strong>
 * <P>
 * Indicates how to handle a pattern's matching and result analysis. Supported Names:
 * <ul>
 * <li>{@code <Bytes>} &ndash; The default tag. Indicates a standard constant, function, or table
 * search.</li>
 * <li>{@code <Blacklist>} &ndash; Unique to function-based searches. Enforces filtering rules.</li>
 * </ul>
 * <p>
 * The pattern's search type is indicated in the parent {@link BpsSearchItem}:
 * <em>OrderedFunction</em>-type and <em>Table</em>-type searches will enforce the order of the
 * buffer as presented in the pattern. See {@link BpsSearchType} for a complete discussion on search
 * types.</li>
 * 
 * <li><strong>buffer</strong>
 * <p>
 * The byte array wrapped in a {@link ByteBuffer}. NOTE: all byte patterns must be in big Endian
 * form.</li>
 * 
 * <li><strong>parentSearchItem</strong>
 * <p>
 * Links to the owning {@code <SearchItem>} tag. This link is needed for result context
 * preservation: when a match is found, the engine extracts metadata from the parent
 * {@link BpsSearchItem} to populate the displayed results. Without this parental link, the results
 * table will have empty gaps and lack critical context.</li>
 * <li><strong>transformation</strong>
 * <p>
 * The transformation details of how this pattern was formed; see {@link BpsTransformation} for
 * details.</li>
 * </ul>
 */
public final class BpsPattern {
	private final String name;
	private ByteBuffer buffer;
	private BpsSearchItem searchItem;
	private final BpsTransformation transformation;

	/**
	 * Constructor.
	 * 
	 * @param name parsed XML tag containing this byte pattern array
	 * @param rawBytes parsed byte array wrapped in a ByteBuffer
	 * @param parentSearchItem parent search item containing this pattern for searching
	 * @param transformationRecord byte manipulation order
	 */
	public BpsPattern(String name, ByteBuffer rawBytes, BpsSearchItem parentSearchItem,
			BpsTransformation transformationRecord) {
		this.name = name;
		this.buffer = rawBytes.duplicate().rewind(); // Safeguard original data integrity
		this.searchItem = parentSearchItem;
		this.transformation = transformationRecord;
	}

	/**
	 * {@return the name as parsed from the XML}
	 */
	public String getName() {
		return name;
	}

	/**
	 * {@return the parent search item containing this byte array}
	 */
	public BpsSearchItem getSearchItem() {
		return searchItem;
	}

	/**
	 * {@return the buffer containing the byte pattern. Downstream consumers are prevented from
	 * corrupting the pattern}
	 */
	public ByteBuffer getBuffer() {
		return buffer.asReadOnlyBuffer().rewind();
	}

	/**
	 * {@return the transformation record of byte manipulations performed on the pattern}
	 */
	public BpsTransformation getTransformation() {
		return transformation;
	}

	@Override
	public String toString() {
		return getDescription();
	}

	/**
	 * {@return the description of the pattern}
	 */
	public String getDescription() {
		ByteBuffer view = getBuffer();
		byte[] bytes = new byte[view.remaining()];
		view.get(bytes);
		String hexBytes = IntStream.range(0, bytes.length)
				.mapToObj(i -> String.format("%02X", bytes[i]))
				.collect(Collectors.joining(" "));
		return String.format("[Pattern Name: %s | Word Size: %s] -> Pattern: %s | Form: [%s]",
			searchItem.getPatternName(),
			searchItem.getWordSize(), hexBytes, transformation.toString());

	}
}
