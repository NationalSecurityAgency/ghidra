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
package help.validator;

import static help.validator.TagProcessor.TagProcessingState.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.LinkedHashMap;

import help.validator.TagProcessor.TagProcessingState;

public class HTMLFileParser {

	private static final String COMMENT_END_TAG = "-->";
	private static final String COMMENT_START_TAG = "!--";

	public static void scanHtmlFile(Path file, TagProcessor tagProcessor) throws IOException {
		InputStreamReader isr = new InputStreamReader(Files.newInputStream(file));
		try (LineNumberReader rdr = new LineNumberReader(isr)) {

			tagProcessor.startOfFile(file);
			String text;
			while ((text = rdr.readLine()) != null) {
				Line line = new Line(file, text, rdr.getLineNumber());
				processLine(line, rdr, file, tagProcessor);
			}
			tagProcessor.endOfFile();
		}
	}

	private static void processLine(Line line, LineNumberReader rdr, Path file,
			TagProcessor tagProcessor) throws IOException {

		if (line == null) {
			// this can happen if we call ourselves recursively
			return;
		}

		int tagStartIndex = -1;
		int tagNameEndIndex = -1;
		String tagType = null;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if (c == '<') {

				boolean isComment = line.regionMatches(i + 1, COMMENT_START_TAG, 0, 3);
				if (isComment) {
					int start = i + COMMENT_START_TAG.length() + 1;
					TagBlock commentBlock = skipPastCommentEnd(rdr, line, start);
					Line next = commentBlock.remainingText;

					//System.out.println("comment: " + commentBlock.tagContent + "\n\t" +
					//	"from file: " + file.getFileName());

					// finish any remaining text on the line
					processLine(next, rdr, file, tagProcessor);
					return;
				}

				tagStartIndex = i;
				ScanResult result = getTagName(line, i + 1);
				tagType = result.text;
				if (tagProcessor.isTagSupported(tagType)) {
					tagNameEndIndex = i + tagType.length() + 1;
					break;
				}

				tagStartIndex = -1;      // reset
				i = result.lastPosition; // keep looking
			}
		}

		// now, finish processing the text on the line, either: the rest of the tag we found, 
		// or the rest of the line when no tag
		if (tagStartIndex < 0) {
			// no tag found
			tagProcessor.processText(line.text);
			return;
		}

		Line precedingText = line.substring(0, tagStartIndex);
		Line remainingText = line.substring(tagNameEndIndex);
		tagProcessor.processText(precedingText.text);

		TagBlock tagBlock = getTagBody(rdr, remainingText);

		String tagBody = tagBlock.tagContent;
		Line postTagText = tagBlock.remainingText;
		int lineNum = rdr.getLineNumber();
		processTag(tagType, tagBody, file, lineNum, tagProcessor);

		processLine(postTagText, rdr, file, tagProcessor);
	}

	private static TagBlock getTagBody(LineNumberReader rdr, Line line) throws IOException {

		String tagBody = "";
		int tagEnd = -1;
		while ((tagEnd = line.indexOf('>')) < 0) {
			tagBody += line.text + " ";
			String nextLineText = rdr.readLine();
			if (nextLineText == null) {
				line = null;
				break;
			}

			line = new Line(line.file, nextLineText, line.lineNumber);
		}

		if (line != null) {
			tagBody += line.substring(0, tagEnd).text;
			line = line.substring(tagEnd + 1);
		}

		TagBlock tag = new TagBlock(line, tagBody);
		return tag;
	}

	private static TagBlock skipPastCommentEnd(LineNumberReader rdr, Line line, int start)
			throws IOException {

		line = line.substring(start);

		String comment = "";
		while (!line.contains(COMMENT_END_TAG)) {
			comment += line.text + '\n';
			String text = rdr.readLine();
			line = new Line(line.file, text, rdr.getLineNumber());
		}

		int index = line.indexOf(COMMENT_END_TAG, 0);
		if (index >= 0) {
			// update the line to move past the comment closing tag 
			comment += line.substring(0, index).text;
			line = line.substring(index + COMMENT_END_TAG.length());
		}

		TagBlock tag = new TagBlock(line, comment);
		return tag;
	}

	private static ScanResult getTagName(Line line, int index) throws IOException {

		int end = index;
		for (int i = index; i < line.length(); i++, end++) {
			char c = line.charAt(i);
			if (c == '<') {
				throw new IOException("Bad tag on line " + line.lineNumber + ": " + line.file);
			}
			if (c == ' ' || c == '\t' || c == '>') {
				return new ScanResult(line.text.substring(index, i), i);
			}
		}

		if (end > index) {
			return new ScanResult(line.text.substring(index, end), end);
		}
		return null;
	}

	private static String processTag(String tagType, String tagBody, Path file, int lineNum,
			TagProcessor tagProcessor) throws IOException {

		if (tagBody.indexOf('<') >= 0 || tagBody.indexOf('>') >= 0) {
			throw new IOException("Bad Tag at line " + lineNum);
		}

		LinkedHashMap<String, String> map = new LinkedHashMap<>();
		StringBuffer buf = new StringBuffer();
		String attr = null;
		TagProcessingState mode = LOOKING_FOR_NEXT_ATTR;
		char term = 0;

		int end = tagBody.length();
		for (int ix = 0; ix < end; ix++) {
			char c = tagBody.charAt(ix);

			switch (mode) {

				case READING_ATTR:
					if (c == '=') {
						attr = buf.toString().toLowerCase();
						mode = LOOKING_FOR_VALUE;
						break;
					}
					if (c == ' ' || c == '\t') {
						attr = buf.toString().toLowerCase();
						map.put(attr, null);
						mode = LOOKING_FOR_NEXT_ATTR;
						break;
					}
					buf.append(c);
					break;

				case LOOKING_FOR_VALUE:
					if (c == ' ' || c == '\t') {
						// we now allow spaces after the '=', but before the '"' starts, as our 
						// tidy tool breaks on the '=' sometimes
						//map.put(attr, null);
						//mode = LOOKING_FOR_NEXT_ATTR;
						break;
					}
					if (c == '"' || c == '\'') {
						buf = new StringBuffer();
						mode = READING_VALUE;
						term = c;
						break;
					}
					buf = new StringBuffer();
					buf.append(c);
					mode = READING_VALUE;
					term = 0;
					break;

				case READING_VALUE:
					if (c == term || (term == 0 && (c == ' ' || c == '\t'))) {
						map.put(attr, buf.toString());
						mode = LOOKING_FOR_NEXT_ATTR;
						break;
					}
					buf.append(c);
					break;

				default:
					if (c == ' ' || c == '\t') {
						continue;
					}
					buf = new StringBuffer();
					buf.append(c);
					mode = READING_ATTR;
			}
		}

		if (mode == READING_ATTR) {
			map.put(buf.toString().toLowerCase(), null);
		}
		else if (mode == LOOKING_FOR_VALUE) {
			map.put(attr, null);
		}
		else if (mode == READING_VALUE) {
			map.put(attr, buf.toString());
		}

		tagProcessor.processTag(tagType, map, file, lineNum);

		buf = new StringBuffer();
		buf.append('<');
		buf.append(tagType);
		Iterator<String> iter = map.keySet().iterator();
		while (iter.hasNext()) {
			attr = iter.next();
			String value = map.get(attr);
			buf.append(' ');
			buf.append(attr);
			if (value != null) {
				buf.append("=\"");
				buf.append(value);
				buf.append("\"");
			}
		}
		buf.append('>');
		return buf.toString();
	}

	private static class Line {
		private Path file;
		private String text;
		private int lineNumber;

		Line(Path file, String text, int lineNumber) {
			this.file = file;
			this.text = text;
			this.lineNumber = lineNumber;
		}

		int indexOf(char c) {
			return text.indexOf(c);
		}

		boolean contains(String s) {
			return text.contains(s);
		}

		Line substring(int from) {
			return new Line(file, text.substring(from), lineNumber);
		}

		Line substring(int from, int exclusiveEnd) {
			return new Line(file, text.substring(from, exclusiveEnd), lineNumber);
		}

		int indexOf(String s, int from) {
			return text.indexOf(s, from);
		}

		boolean regionMatches(int from, String s, int ooffset, int len) {
			return text.regionMatches(from, s, ooffset, len);
		}

		char charAt(int i) {
			return text.charAt(i);
		}

		int length() {
			return text.length();
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" +
				"\tfile: " + file.getFileName() + ",\n" +
				"\tline_number: " + lineNumber + ",\n" +
				"\ttext: " + text + "\n" +
			"}";
			//@formatter:on
		}
	}

	// container to hold the result text of a search, as well as the last index checked
	private static class ScanResult {
		private String text;
		private int lastPosition;

		ScanResult(String text, int lastPosition) {
			this.text = text;
			this.lastPosition = lastPosition;
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" +
				"\ttext: " + text + ",\n" +
				"\tlast_position: " + lastPosition + "\n" +
			"}";
			//@formatter:on
		}
	}

	private static class TagBlock {

		private Line remainingText;
		private String tagContent;

		TagBlock(Line remainingText, String tagContent) {
			this.remainingText = remainingText;
			this.tagContent = tagContent;
		}

		@Override
		public String toString() {
			//@formatter:off
			return "{\n" +
				"\tcontent: " + tagContent + ",\n" +
				"\tpost_text: " + remainingText + "\n" +
			"}";
			//@formatter:on
		}
	}
}
