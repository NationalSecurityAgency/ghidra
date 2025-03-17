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
package ghidra.app.plugin.core.search;

import java.util.*;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import generic.json.Json;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.parallel.*;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContext;
import ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceContextBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utility.function.Dummy;

/**
 * Searches for the given pattern in all functions in the given program.
 */
public class DecompilerTextFinder {

	/**
	 * Finds text inside decompiled functions using the given pattern.
	 * @param program the program
	 * @param searchPattern the search pattern
	 * @param consumer the consumer that will get matches
	 * @param monitor the task monitor
	 * @see #findText(Program, Pattern, Collection, Consumer, TaskMonitor)
	 */
	public void findText(Program program, Pattern searchPattern, Consumer<TextMatch> consumer,
			TaskMonitor monitor) {

		monitor = TaskMonitor.dummyIfNull(monitor);
		StringFinderCallback callback = new StringFinderCallback(program, searchPattern, consumer);

		Listing listing = program.getListing();
		FunctionIterator functions = listing.getFunctions(true);

		doFindText(program, functions, callback, monitor);
	}

	/**
	 * Finds text inside the given decompiled functions using the given pattern.
	 * @param program the program
	 * @param searchPattern the search pattern
	 * @param functions the functions to search
	 * @param consumer the consumer that will get matches
	 * @param monitor the task monitor
	 * @see #findText(Program, Pattern, Consumer, TaskMonitor)
	 */
	public void findText(Program program, Pattern searchPattern, Iterator<Function> functions,
			Consumer<TextMatch> consumer, TaskMonitor monitor) {

		monitor = TaskMonitor.dummyIfNull(monitor);
		StringFinderCallback callback = new StringFinderCallback(program, searchPattern, consumer);
		doFindText(program, functions, callback, monitor);
	}

	/**
	 * Finds text inside the given decompiled functions using the given pattern.
	 * @param program the program
	 * @param searchPattern the search pattern
	 * @param functions the functions to search
	 * @param consumer the consumer that will get matches
	 * @param monitor the task monitor
	 * @see #findText(Program, Pattern, Consumer, TaskMonitor)
	 */
	public void findText(Program program, Pattern searchPattern, Collection<Function> functions,
			Consumer<TextMatch> consumer, TaskMonitor monitor) {

		monitor = TaskMonitor.dummyIfNull(monitor);
		StringFinderCallback callback = new StringFinderCallback(program, searchPattern, consumer);
		doFindText(functions, callback, monitor);
	}

	private void doFindText(Collection<Function> functions, StringFinderCallback callback,
			TaskMonitor monitor) {

		try {
			ParallelDecompiler.decompileFunctions(callback, functions, monitor);

		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // reset the flag
			if (!monitor.isCancelled()) {
				Msg.debug(this, "Interrupted while decompiling functions");
			}
		}
		catch (Exception e) {
			Msg.error(this, "Encountered an exception decompiling functions", e);
		}
		finally {
			callback.dispose();
		}
	}

	private void doFindText(Program program, Iterator<Function> functions,
			StringFinderCallback callback, TaskMonitor monitor) {

		Consumer<Void> dummy = Dummy.consumer();

		try {
			ParallelDecompiler.decompileFunctions(callback, program, functions, dummy, monitor);

		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt(); // reset the flag
			if (!monitor.isCancelled()) {
				Msg.debug(this, "Interrupted while decompiling functions");
			}
		}
		catch (Exception e) {
			Msg.error(this, "Encountered an exception decompiling functions", e);
		}
		finally {
			callback.dispose();
		}
	}

	private static class StringFinderCallback extends DecompilerCallback<Void> {

		private Consumer<TextMatch> callback;
		private Pattern pattern;
		private String searchText;

		StringFinderCallback(Program program, Pattern pattern, Consumer<TextMatch> callback) {
			super(program, new DecompilerConfigurer());
			this.pattern = pattern;
			this.callback = callback;
			this.searchText = pattern.pattern();
		}

		@Override
		public Void process(DecompileResults results, TaskMonitor monitor) throws Exception {

			Function function = results.getFunction();
			if (function.isThunk()) {
				return null;
			}

			ClangTokenGroup tokens = results.getCCodeMarkup();
			if (tokens == null) {
				return null;
			}
			List<ClangLine> lines = DecompilerUtils.toLines(tokens);

			// (?s) - enable dot all mode
			// (?-s) - disable dot all mode
			boolean multiLine = (pattern.flags() & Pattern.DOTALL) == Pattern.DOTALL;
			if (multiLine) {
				performMultiLineSearch(function, lines);
			}
			else {
				// line-by-line search
				for (ClangLine cLine : lines) {
					findMatch(function, cLine);
				}
			}

			return null;
		}

		private void performMultiLineSearch(Function function, List<ClangLine> lines) {

			// Map characters to lines so we can later translate a character position into the line
			// that contains it.  Also convert all lines into one big run of text to use with the
			// regex.  Also, turn the c line into a String for later searching.
			StringBuilder buffy = new StringBuilder();
			TreeMap<Integer, TextLine> linesRangeMap = new TreeMap<>();
			int pos = 0;
			for (ClangLine cLine : lines) {
				String text = PrettyPrinter.getText(cLine);
				buffy.append(text).append('\n');
				TextLine textLine = new TextLine(pos, cLine, text);
				linesRangeMap.put(pos, textLine);
				pos += text.length() + 1; // +1 for newline
			}

			Matcher matcher = pattern.matcher(buffy);
			findMatches(function, linesRangeMap, matcher);
		}

		/**
		 * Uses the given matcher to search for all matches, which may span multiple lines.
		 */
		private void findMatches(Function function, TreeMap<Integer, TextLine> linesRangeMap,
				Matcher matcher) {

			while (matcher.find()) {
				emitTextMatch(function, linesRangeMap, matcher);
			}
		}

		private void emitTextMatch(Function function, TreeMap<Integer, TextLine> linesRangeMap,
				Matcher matcher) {

			List<TextLine> lineMatches = new ArrayList<>();

			int pos = 0;
			int start = matcher.start();
			int end = matcher.end();
			for (pos = start; pos < end; pos++) {

				// grab the line that contains the current character position
				TextLine line = linesRangeMap.floorEntry(pos).getValue();

				// This will be positive if the current line contains the match start character.
				// In this case, let the line know it has the start.  If we don't set the start,
				// then the line match will start at 0.
				int lineStartOffset = start - line.getOffset(); // relative offset
				if (lineStartOffset >= 0) {
					line.setMatchStart(lineStartOffset);
				}

				// In this case, let the line know it has the end.  If we don't set the end, 
				// then the line match will end at the end of the line.
				if (end <= line.getEndOffset()) {
					int relativeEnd = end - line.getOffset();
					line.setMatchEnd(relativeEnd);
				}

				lineMatches.add(line);
				pos = line.getEndOffset();
			}

			// Use the first line for attributes of the match, like line number and address
			TextLine firstLine = lineMatches.get(0);
			int lineNumber = firstLine.getLineNumber();
			AddressSet addresses = getAddresses(function, firstLine.getCLine());
			LocationReferenceContext context = createMatchContext(lineMatches);
			TextMatch match =
				new TextMatch(function, addresses, lineNumber, searchText, context, true);
			callback.accept(match);
		}

		private LocationReferenceContext createMatchContext(List<TextLine> matches) {

			LocationReferenceContextBuilder builder = new LocationReferenceContextBuilder();
			for (TextLine line : matches) {
				if (!builder.isEmpty()) {
					builder.newline();
				}

				String text = line.getText();
				int start = line.getMatchStart();
				int end = line.getMatchEnd();
				builder.append(text.substring(0, start));
				builder.appendMatch(text.substring(start, end));
				builder.append(text.substring(end, line.length()));
			}

			return builder.build();
		}

		private void findMatch(Function function, ClangLine line) {

			String textLine = PrettyPrinter.getText(line);
			Matcher matcher = pattern.matcher(textLine);
			if (!matcher.find()) {
				return;
			}

			LocationReferenceContextBuilder builder = new LocationReferenceContextBuilder();

			int start = matcher.start();
			int end = matcher.end();
			builder.append(textLine.substring(0, start));
			builder.appendMatch(textLine.substring(start, end));
			if (end < textLine.length()) {
				builder.append(textLine.substring(end));
			}

			int lineNumber = line.getLineNumber();
			AddressSet addresses = getAddresses(function, line);
			LocationReferenceContext context = builder.build();
			TextMatch match =
				new TextMatch(function, addresses, lineNumber, searchText, context, false);
			callback.accept(match);
		}

		private AddressSet getAddresses(Function function, ClangLine line) {
			Program program = function.getProgram();
			AddressSpace space = function.getEntryPoint().getAddressSpace();
			List<ClangToken> tokens = line.getAllTokens();
			return DecompilerUtils.findClosestAddressSet(program, space, tokens);
		}

		/**
		 * A text line represents a ClangLine, it's pretty text, its character position in the 
		 * overall body of text and the character positions of the portion of text that has matched
		 * a search.  A line may have a search match that is partial or the entire line may match
		 * the search, such as in a multi-line match.
		 */
		private class TextLine {
			private ClangLine cLine;
			private int offset; // the character offset into the entire body of text
			private String text;

			// relative offsets
			private int matchStart;
			private int matchEnd;

			TextLine(int offset, ClangLine cLine, String text) {
				this.cLine = cLine;
				this.offset = offset;
				this.text = text;

				matchStart = 0;
				matchEnd = text.length();
			}

			ClangLine getCLine() {
				return cLine;
			}

			int length() {
				return text.length();
			}

			int getOffset() {
				return offset;
			}

			int getEndOffset() {
				return offset + length();
			}

			int getLineNumber() {
				return cLine.getLineNumber();
			}

			String getText() {
				return text;
			}

			int getMatchStart() {
				return matchStart;
			}

			int getMatchEnd() {
				return matchEnd;
			}

			void setMatchStart(int matchStart) {
				this.matchStart = matchStart;
			}

			void setMatchEnd(int matchEnd) {
				this.matchEnd = matchEnd;
			}

			@Override
			public String toString() {
				return Json.toString(this);
			}
		}
	}

	private static class DecompilerConfigurer implements DecompileConfigurer {

		@Override
		public void configure(DecompInterface decompiler) {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");

			DecompileOptions xmlOptions = new DecompileOptions();
			xmlOptions.setDefaultTimeout(60);
			decompiler.setOptions(xmlOptions);
		}
	}

}
