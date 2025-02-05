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
package ghidra.doclets.typestubs;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.lang.model.element.Element;

import com.sun.source.doctree.DocTree;

/**
 * Helper class for converting an HTML table to reStructuredText
 */
final class RstTableBuilder {

	// give each column enough padding to allow an alignment
	private static final int COLUMN_PADDING = 2;

	private final HtmlConverter docConverter;
	private final Element el;
	private Row columns = new Row();
	private List<Row> rows = new ArrayList<>();
	private Row currentRow = null;
	private List<Integer> columnWidths = new ArrayList<>();
	private String caption = null;

	/**
	 * Creates a new {@link RstTableBuilder}
	 *
	 * @param docConverter the html converter
	 * @param el the element
	 */
	RstTableBuilder(HtmlConverter docConverter, Element el) {
		this.docConverter = docConverter;
		this.el = el;
	}

	/**
	 * Adds new row group to the table
	 *
	 * @param tree the html tree containing the row group
	 * @throws UnsupportedOperationException if any row in the group contains a nested row
	 */
	void addRowGroup(HtmlDocTree tree) {
		switch (tree.getHtmlKind()) {
			case THEAD:
				if (tree.getBody().size() > 1) {
					throw new UnsupportedOperationException("nested table rows are not supported");
				}
			case TBODY:
			case TFOOT:
				for (DocTree tag : tree.getBody()) {
					if (!(tag instanceof HtmlDocTree)) {
						continue;
					}
					addRow((HtmlDocTree) tag);
				}
				return;
			default:
				break;
		}
	}

	/**
	 * Adds new row to the table
	 *
	 * @param tree the html tree containing the row
	 * @throws UnsupportedOperationException if the row contains a nested row
	 */
	void addRow(HtmlDocTree tree) {
		if (currentRow == null) {
			currentRow = columns;
		}
		else {
			currentRow = new Row();
			rows.add(currentRow);
		}
		boolean columnsDone = columns.size() > 0;
		for (DocTree tag : tree.getBody()) {
			if (!(tag instanceof HtmlDocTree)) {
				continue;
			}
			HtmlDocTree html = (HtmlDocTree) tag;
			String align = docConverter.getAttributes(el, html.getStartTag()).get("align");
			switch (html.getHtmlKind()) {
				case TH:
					if (columnsDone) {
						// vertical headers
						// insert it as an entry so it at least comes out ok
						addEntry(getBody(html), align);
					}
					else {
						addColumn(getBody(html), align);
					}
					break;
				case TD:
					addEntry(getBody(html), align);
					break;
				case TR:
					throw new UnsupportedOperationException("nested table rows are not supported");
				default:
					break;
			}
		}
	}

	/**
	 * Adds a caption to the table
	 *
	 * @param caption the caption
	 */
	void addCaption(String caption) {
		if (!caption.isBlank()) {
			this.caption = caption;
		}
	}

	/**
	 * Builds the reStructuredText formatted table
	 *
	 * @return the reStructuredText table
	 */
	String build() {
		StringBuilder builder = new StringBuilder();
		builder.append('\n');

		if (caption != null) {
			int length = caption.length();
			builder.repeat('^', length)
					.append('\n');
			builder.append(caption)
					.append('\n')
					.repeat('^', length)
					.append('\n');
		}

		buildRowBorder(builder, '-');
		columns.build(builder);
		buildRowBorder(builder, '=');

		for (Row row : rows) {
			row.build(builder);
			buildRowBorder(builder, '-');
		}

		return builder.toString();
	}

	/**
	 * Adds a column to the table
	 *
	 * @param value the column value
	 * @param align the column alignment
	 */
	private void addColumn(String value, String align) {
		if (align == null) {
			align = "CENTER";
		}
		addColumn(value, Alignment.valueOf(align.toUpperCase()));
	}

	/**
	 * Adds a column to the table
	 *
	 * @param value the column value
	 * @param align the column alignment
	 */
	private void addColumn(String value, Alignment align) {
		int column = columns.size();
		columns.addValue(value, align);
		growColumn(value, column);
	}

	/**
	 * Adds an entry to the current row in the table
	 *
	 * @param value the entry value
	 * @param align the entry alignment
	 */
	private void addEntry(String value, String align) {
		if (align == null) {
			align = "LEFT";
		}
		addEntry(value, Alignment.valueOf(align.toUpperCase()));
	}

	/**
	 * Adds an entry to the current row in the table
	 *
	 * @param value the entry value
	 * @param align the entry alignment
	 */
	private void addEntry(String value, Alignment align) {
		int column = currentRow.size();
		currentRow.addValue(value, align);
		growColumn(value, column);
	}

	/**
	 * Helper method to get the converted contents of an html tree
	 *
	 * @param tag the html
	 * @return the converted html
	 */
	private String getBody(HtmlDocTree tag) {
		return docConverter.convertTree(el, tag.getBody());
	}

	/**
	 * Creates a row border with the provided character
	 *
	 * @param builder the string builder
	 * @param c the border character
	 */
	private void buildRowBorder(StringBuilder builder, char c) {
		builder.append('+');
		for (int width : columnWidths) {
			builder.repeat(c, width)
					.append('+');
		}
		builder.append('\n');
	}

	/**
	 * Computes the max line width for the provided multi-line text
	 *
	 * @param text the text
	 * @return the max line width
	 */
	private static int getLineWidth(String text) {
		// value may be mutiple lines
		return text.lines()
				.map(String::stripLeading)
				.mapToInt(String::length)
				.max()
				.getAsInt();
	}

	/**
	 * Grows the provided column appropriately for the newly added value
	 *
	 * @param value the newly added value
	 * @param column the column number
	 */
	private void growColumn(String value, int column) {
		int length = !value.isEmpty() ? getLineWidth(value) + COLUMN_PADDING : COLUMN_PADDING;
		if (column >= columnWidths.size()) {
			columnWidths.add(length);
			return;
		}
		if (columnWidths.get(column) < length) {
			columnWidths.set(column, length);
		}
	}

	/**
	 * Aligns the single line value according to the column width and alignment
	 *
	 * @param value the value to align
	 * @param columnWidth the column width
	 * @param align the alignment
	 * @return the aligned value
	 */
	private static String alignSingleLine(String value, int columnWidth, Alignment align) {
		int length = value.length();
		return switch (align) {
			case LEFT -> value + " ".repeat(columnWidth - length);
			case CENTER -> {
				int left = (columnWidth - length) / 2;
				int right = left;
				if (left + right + length < columnWidth) {
					right++;
				}
				yield " ".repeat(left) + value + " ".repeat(right);
			}
			case RIGHT -> " ".repeat(columnWidth - length) + value;
		};
	}

	private static enum Alignment {
		LEFT,
		CENTER,
		RIGHT
	}

	/**
	 * Helper class for modeling a table row
	 */
	private class Row {
		int maxLines = 1;
		List<List<String>> values = new ArrayList<>();
		List<Alignment> alignments = new ArrayList<>();

		/**
		 * Adds the value to the row
		 *
		 * @param value the value
		 * @param align the alignment
		 */
		void addValue(String value, Alignment align) {
			List<String> lines = value.lines()
					.map(String::stripLeading)
					.collect(Collectors.toList());
			if (lines.size() > maxLines) {
				maxLines = lines.size();
			}
			values.add(lines);
			alignments.add(align);
		}

		/**
		 * Gets the size of this row
		 *
		 * @return the row size
		 */
		int size() {
			return values.size();
		}

		/**
		 * Appends this row to the provided string builder
		 *
		 * @param builder the string builder
		 */
		void build(StringBuilder builder) {
			for (int i = 0; i < maxLines; i++) {
				builder.append('|');
				for (int j = 0; j < values.size(); j++) {
					List<String> entry = values.get(j);
					String value;
					if (i >= entry.size()) {
						value = " ".repeat(columnWidths.get(j));
					}
					else {
						value = alignSingleLine(j, entry.get(i));
					}
					builder.append(value)
							.append('|');
				}
				builder.append('\n');
			}
		}

		/**
		 * Aligns the provided single line value according to the column and its alignent
		 *
		 * @param column the column number
		 * @param value the single line value
		 * @return the aligned value
		 */
		String alignSingleLine(int column, String value) {
			int columnLength = columnWidths.get(column);
			return RstTableBuilder.alignSingleLine(value, columnLength, alignments.get(column));
		}
	}
}
