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
package ghidra.util;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

public class JavaSourceFile {

	private final String filename;

	private final List<JavaSourceLine> linesList = new ArrayList<>();
	private int initialLineCount;

	public JavaSourceFile(String filename) {
		this.filename = filename;
		loadFile();
		initialLineCount = linesList.size();
	}

	// copy constructor
	private JavaSourceFile(String filename, List<JavaSourceLine> originalLines) {
		this.filename = filename;
		this.linesList.addAll(originalLines);
		this.initialLineCount = linesList.size();
	}

	private void loadFile() {
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader(filename));

			String newline = System.getProperty("line.separator");
			int lineNumber = 0;
			String line = null;
			while ((line = reader.readLine()) != null) {
				linesList.add(new JavaSourceLine(line + newline, ++lineNumber));
			}

		}
		catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if (reader != null) {
				try {
					reader.close();
				}
				catch (IOException e) { // we tried 					
				}
			}
		}
	}

	public boolean hasChanges() {
		return initialLineCount != linesList.size() || hasLineChanges();
	}

	private boolean hasLineChanges() {
		for (JavaSourceLine line : linesList) {
			if (line.hasChanges()) {
				return true;
			}
		}
		return false;
	}

	public int getImportSectionStartLineNumber() {
		for (JavaSourceLine line : linesList) {
			String text = line.getText();
			if (text.trim().startsWith("import")) {
				return line.getLineNumber();
			}
		}
		return -1;
	}

	public int getLineNumberAfterStatementAtLine(int lineNumber) {
		JavaSourceLine startLine = getStatementStartForLine(lineNumber);
		if (startLine.getText().trim().endsWith(";")) {
			return lineNumber + 1;
		}

		List<JavaSourceLine> statementLines =
			getRemainingLinesForStatement(startLine, startLine.getLineNumber() + 1);
		JavaSourceLine lastLine = statementLines.get(statementLines.size() - 1);
		return lastLine.getLineNumber() + 1;
	}

	public void removeJavaStatement(int lineNumber) {
		JavaSourceLine startLine = getStatementStartForLine(lineNumber);
		if (startLine.getText().trim().endsWith(";")) {
			startLine.delete(); // statement is all on one line, nothing more to do
			return;
		}

		List<JavaSourceLine> linesToClear = new ArrayList<>(
			getRemainingLinesForStatement(startLine, startLine.getLineNumber() + 1));
		linesToClear.add(0, startLine);

		int size = linesToClear.size();
		for (int i = 0; i < size - 1; i++) {
			linesToClear.get(i).delete();
		}

		// do the last line special
		JavaSourceLine lastLine = linesToClear.get(size - 1);
		String text = lastLine.getText();
		int count = StringUtils.countMatches(text, ';');
		if (count == 1) {
			// normal line
			lastLine.delete();
			return;
		}

		// remove all text up to the first semicolon
		text = text.substring(text.indexOf(";") + 1);
		lastLine.setText(text);
	}

	private List<JavaSourceLine> getRemainingLinesForStatement(JavaSourceLine statementStart,
			int startLineNumber) {

		TokenPairMatcher parenMatcher = new TokenPairMatcher('(', ')');
		TokenPairMatcher braceMatcher = new TokenPairMatcher('{', '}');
		String text = statementStart.getText();
		parenMatcher.scanLine(text);
		braceMatcher.scanLine(text);

		List<JavaSourceLine> list = new ArrayList<>();
		startLineNumber -= 1; // internally zero-based
		List<JavaSourceLine> remainingList = linesList.subList(startLineNumber, linesList.size());
		for (JavaSourceLine sourceLine : remainingList) {
			list.add(sourceLine);
			if (isValidEndOfStatement(parenMatcher, braceMatcher, sourceLine)) {
				break; // found the end!
			}
		}
		return list;
	}

	private boolean isValidEndOfStatement(TokenPairMatcher parenMatcher,
			TokenPairMatcher braceMatcher, JavaSourceLine sourceLine) {

		String text = sourceLine.getText();
		parenMatcher.scanLine(text);
		braceMatcher.scanLine(text);

		if (!parenMatcher.isBalanced() || !braceMatcher.isBalanced()) {
			return false;
		}

		return text.trim().endsWith(";");
	}

	public JavaSourceLine getLineContaintingStatementStart(int lineNumber) {
		return getStatementStartForLine(lineNumber);
	}

	public String getJavaStatementStartingAtLine(int firstUseLineNumber) {
		JavaSourceLine startLine = getStatementStartForLine(firstUseLineNumber);
		String lineText = startLine.getText();
		if (lineText.trim().endsWith(";")) {
			return lineText;
		}

		StringBuffer buffy = new StringBuffer(startLine.getText());
		List<JavaSourceLine> statementLines =
			getRemainingLinesForStatement(startLine, startLine.getLineNumber() + 1);
		for (JavaSourceLine sourceLine : statementLines) {
			buffy.append(sourceLine.getText().trim());
		}
		return buffy.toString();
	}

	private JavaSourceLine getStatementStartForLine(int lineNumber) {
		JavaSourceLine backwardsLine = getStatementFromNextSemicolon(lineNumber);
		if (backwardsLine != null) {
			return backwardsLine;
		}

		int currentLineNumber = lineNumber;
		TokenMatcher semicolonMatcher = new TokenMatcher(';');
		TokenMatcher equalsMatcher = new TokenMatcher('=');
		JavaSourceLine line = getLine(currentLineNumber);

		String text = line.getText();
		equalsMatcher.scanLine(text);
		if (equalsMatcher.foundToken()) {
			return line; // our line contains an assignment
		}

		// start looking backwards until we hit an equals or semicolon
		line = getLine(--currentLineNumber);
		text = line.getText();
		while (true) {
			equalsMatcher.scanLine(text);
			if (equalsMatcher.foundToken()) {
				return line; // an assignment means the start of a line
			}

			semicolonMatcher.scanLine(text);
			if (semicolonMatcher.foundToken()) {
				// found an end-of-statement for a previous statement
				return findNextNonBlankLine(++currentLineNumber);
			}

			line = getLine(--currentLineNumber);
			text = line.getText();
		}
	}

	private JavaSourceLine getStatementFromNextSemicolon(int lineNumber) {
		// see if we are at the end of a line and can walk backwards to find the entire statement
		JavaSourceLine lastLine = findEndOfUnknownLine(lineNumber);

		if (isValidStatement(lastLine)) {
			return lastLine;
		}

		TokenPairMatcher parenMatcher = new TokenPairMatcher('(', ')');
		TokenPairMatcher braceMatcher = new TokenPairMatcher('{', '}');

		JavaSourceLine lastLineSeenFromStatement = null;
		int startOffset = lastLine.getLineNumber();
		int searchLineOffset = startOffset;
		do {
			JavaSourceLine searchLine = getLine(searchLineOffset--);
			String text = searchLine.getText();
			parenMatcher.scanLine(text);
			braceMatcher.scanLine(text);

			// ignore special cases
			if (text.contains("serialVersion")) {
				continue;
			}

			TokenMatcher semicolonMatcher = new TokenMatcher(';');
			semicolonMatcher.scanLine(text);
			if (semicolonMatcher.foundToken() && (startOffset != searchLineOffset + 1) &&
				lastLineSeenFromStatement != null) {
				return findNextNonBlankLine(lastLineSeenFromStatement.getLineNumber());
			}

			TokenMatcher equalsMatcher = new TokenMatcher('=');
			equalsMatcher.scanLine(text);
			if (equalsMatcher.foundToken()) {
				if (containsActionAssignment(text)) {
					return searchLine;
				}

//                if ( parenMatcher.isBalanced() && braceMatcher.isBalanced() ) {
//                    return searchLine;
//                }
			}

			if (text.contains("(") || text.contains(".")) {
				lastLineSeenFromStatement = searchLine;
			}

		}
		while (searchLineOffset > 0);

		return null; // shouldn't get here
	}

	private boolean isValidStatement(JavaSourceLine lastLine) {
		String text = lastLine.getText().trim();
		if (!text.endsWith(";")) {
			return false;
		}

		TokenPairMatcher parenMatcher = new TokenPairMatcher('(', ')');
		TokenPairMatcher braceMatcher = new TokenPairMatcher('{', '}');
		parenMatcher.scanLine(text);
		braceMatcher.scanLine(text);
		return parenMatcher.isBalanced() && braceMatcher.isBalanced();
	}

	private boolean containsActionAssignment(String text) {
		String[] equalsParts = text.split("=");
		String leftHandSide = equalsParts[0];
		String[] nameAndMaybeDeclaraction = leftHandSide.trim().split("\\s");
		if (nameAndMaybeDeclaraction.length == 2) {
			return nameAndMaybeDeclaraction[0].endsWith("Action");
		}
		return StringUtils.containsIgnoreCase(nameAndMaybeDeclaraction[0], "action");
	}

	private JavaSourceLine findEndOfUnknownLine(int lineNumber) {
		JavaSourceLine currentLine = getLine(lineNumber);
		if (currentLine.getText().trim().endsWith(";")) {
			return currentLine;
		}

		List<JavaSourceLine> list = new ArrayList<>();
		int startLineNumber = lineNumber;
		List<JavaSourceLine> remainingList = linesList.subList(startLineNumber, linesList.size());
		for (JavaSourceLine sourceLine : remainingList) {
			list.add(sourceLine);
			if (sourceLine.getText().trim().endsWith(";")) {
				break; // found the end!
			}
		}

		return list.get(list.size() - 1);
	}

	private JavaSourceLine findNextNonBlankLine(int lineNumber) {
		do {
			JavaSourceLine line = getLine(lineNumber++);
			if (!line.getText().trim().equals("")) {
				return line;
			}
		}
		while (true);
	}

	public JavaSourceLine getLine(int oneBasedLineNumber) {
		if (oneBasedLineNumber <= 0 || oneBasedLineNumber > linesList.size()) {
			throw new IndexOutOfBoundsException(
				"File does not contain line number: " + oneBasedLineNumber);
		}

		return linesList.get(oneBasedLineNumber - 1);
	}

	public void save() {
		System.err.println("save on file: " + filename);

		if (!hasChanges()) {
			System.err.println("\tno changes to: " + filename);
			return;
		}

		FileWriter fileWriter = null;
		try {
			fileWriter = new FileWriter(filename);
			doWrite(new PrintWriter(fileWriter));

		}
		catch (IOException e) {
			e.printStackTrace();
		}
		finally {
			if (fileWriter != null) {
				try {
					fileWriter.close();
				}
				catch (IOException e) {
					// we tried
				}
			}
		}

//		doWrite( new PrintWriter( System.err ) );

	}

	private void doWrite(PrintWriter writer) {
		for (JavaSourceLine line : linesList) {
			writer.write(line.getText());
		}
		writer.flush();
	}

	@Override
	public String toString() {
		return filename;
	}

	public JavaSourceFile getOriginalSourceFileCopy() {
		return new JavaSourceFile(filename, copyOriginalLines());
	}

	private List<JavaSourceLine> copyOriginalLines() {
		List<JavaSourceLine> newList = new ArrayList<>();
		for (JavaSourceLine line : linesList) {
			newList.add(line.createOriginalClone());
		}
		return newList;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TokenMatcher {
		private final char token;
		private boolean foundToken;

		private TokenMatcher(char token) {
			this.token = token;
		}

		void scanLine(String line) {
			if (foundToken) {
				return;
			}

			int length = line.length();
			for (int i = 0; i < length; i++) {
				char charAt = line.charAt(i);
				if (charAt == token) {
					foundToken = true;
					break;
				}
			}
		}

		boolean foundToken() {
			return foundToken;
		}
	}

	private class TokenPairMatcher {
		int runningTokenCount; // can be negative 
		private final char leftToken;
		private final char rightToken;

		private TokenPairMatcher(char leftToken, char rightToken) {
			this.leftToken = leftToken;
			this.rightToken = rightToken;
		}

		void scanLine(String line) {
			int length = line.length();
			for (int i = 0; i < length; i++) {
				char charAt = line.charAt(i);
				if (charAt == leftToken) {
					runningTokenCount++;
				}
				else if (charAt == rightToken) {
					runningTokenCount--;
				}
			}
		}

		boolean isBalanced() {
			return runningTokenCount == 0;
		}

		@Override
		public String toString() {
			return "TokenMatcher: [" + leftToken + ", " + rightToken + "] - count: " +
				runningTokenCount;
		}
	}
}
