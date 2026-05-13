/* ###
 * IP: Apache License 2.0
 */

/*
 * Ported and adapted from rustc-demangle (https://github.com/rust-lang/rustc-demangle),
 * which is dual-licensed under Apache-2.0 and MIT. This implementation is
 * derived from commit c5688cfec32d2bd00701836f12beb3560ee015b8 and adjusted
 * for Ghidra’s Java runtime.
 */
package ghidra.app.plugin.core.analysis.rust.demangler;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A class that will demangle Rust symbols mangled according to the V0 format. This class
 * implements the grammar that will translate a mangled string into a demangled one.
 * 
 * @see <a href="https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html">2603-rust-symbol-name-mangling-v0.html</a>
 */
public final class RustDemanglerV0 {

	public static final String RECURSION_LIMIT_MESSAGE = "{recursion limit reached}";

	public static final int MAX_DEPTH = 500;

	private RustDemanglerV0() {
		// utility class
	}

	/**
	 * Demangles a symbol according to the format
	 * @param symbol the mangled symbol name
	 * @return the demangled symbol name
	 */
	public static String demangle(String symbol) {
		return demangleInternal(symbol, false);
	}

	/**
	 * Demangles a Rust V0 mangled symbol using an alternate format that omits
	 * hash/disambiguator suffixes.
	 *
	 * @param symbol the mangled symbol
	 * @return the demangled representation without hash suffixes, or {@code null} if the input is not
	 *         a valid V0-mangled symbol
	 */
	public static String demangleAlternate(String symbol) {
		return demangleInternal(symbol, true);
	}

	private static String demangleInternal(String symbol, boolean alternate) {
		if (symbol == null || symbol.isEmpty()) {
			return null;
		}

		String inner = stripPrefix(symbol);
		if (inner == null || inner.isEmpty()) {
			return null;
		}

		if (!isAscii(inner)) {
			return null;
		}

		if (!startsWithUpperPath(inner)) {
			return null;
		}

		try {
			Parser parser = new Parser(inner);

			try {
				Parser afterFirst = Printer.dryRunParsePath(parser.copy(), false, alternate);
				if (startsWithUpperPath(afterFirst)) {
					Printer.dryRunParsePath(afterFirst, false, alternate);
				}
			}
			catch (ParseException e) {
				if (e.isRecursedTooDeep()) {
					return null;
				}
				return null;
			}

			Printer printer = new Printer(parser.copy(), new StringBuilder(), alternate);
			printer.printPath(true);
			String result = printer.finish();
			String suffix = printer.remaining();
			if (!suffix.isEmpty()) {
				boolean keepSuffix = suffix.startsWith(".") && !suffix.startsWith(".llvm") &&
					!suffix.startsWith("@@");
				if (!keepSuffix) {
					suffix = "";
				}
			}
			return suffix.isEmpty() ? result : result + suffix;
		}
		catch (ParseException e) {
			if (e.isRecursedTooDeep()) {
				return e.message();
			}
			return null;
		}
	}

	/**
	 * Removes known rust prefixes
	 * @param symbol the string substring
	 * @return if the strip succeeded
	 */
	private static String stripPrefix(String symbol) {
		if (symbol.length() > 2 && symbol.startsWith("_R")) {
			return symbol.substring(2);
		}
		if (symbol.length() > 1 && symbol.startsWith("R")) {
			return symbol.substring(1);
		}
		if (symbol.length() > 3 && symbol.startsWith("__R")) {
			return symbol.substring(3);
		}
		return null;
	}

	/**
	 * Returns true if every character in {@code text} is ASCII. Legacy demangler performed the
	 * same check up-front before attempting to walk the grammar.
	 */
	private static boolean isAscii(String text) {
		for (int i = 0; i < text.length(); i++) {
			if (text.charAt(i) >= 0x80) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Rust v0 manglings always begin with a capital letter describing the top-level path kind.
	 */
	private static boolean startsWithUpperPath(String text) {
		if (text == null || text.isEmpty()) {
			return false;
		}
		char c = text.charAt(0);
		return c >= 'A' && c <= 'Z';
	}

	private static boolean startsWithUpperPath(Parser parser) {
		int peek = parser.peek();
		return peek >= 'A' && peek <= 'Z';
	}

	private enum ParseErrorKind {
		INVALID,
		RECURSED_TOO_DEEP
	}

	private static final class ParseException extends Exception {
		private static final long serialVersionUID = 1L;
		final ParseErrorKind kind;

		ParseException(ParseErrorKind kind) {
			this.kind = kind;
		}

		boolean isRecursedTooDeep() {
			return kind == ParseErrorKind.RECURSED_TOO_DEEP;
		}

		String message() {
			return switch (kind) {
				case RECURSED_TOO_DEEP -> RECURSION_LIMIT_MESSAGE;
				case INVALID -> "{invalid syntax}";
			};
		}
	}

	/**
	 * Stateful cursor used while walking the v0 grammar. The parser owns the original
	 * mangled string, maintains the current offset, and keeps a recursion counter so we can
	 * mirror rustc's depth limits when following backrefs.
	 */
	private static final class Parser {
		private final String sym;
		private int next;
		private int depth;

		Parser(String sym) {
			this(sym, 0, 0);
		}

		Parser(String sym, int next, int depth) {
			this.sym = sym;
			this.next = next;
			this.depth = depth;
		}

		Parser copy() {
			return new Parser(sym, next, depth);
		}

		/**
		 * Returns the remaining string to be demangled
		 * @return the mangled string
		 */
		String remaining() {
			return sym.substring(next);
		}

		/**
		 * @return the next character without consuming it, or {@code -1} if the cursor is exhausted.
		 */
		int peek() {
			if (next >= sym.length()) {
				return -1;
			}
			return sym.charAt(next);
		}

		/**
		 * Advances the cursor when the next character matches {@code expected}.
		 * @param expected the expected character
		 * @return true if advanced
		 */
		boolean eat(char expected) {
			if (peek() == expected) {
				next++;
				return true;
			}
			return false;
		}

		/**
		 * Consumes and returns the next character.
		 * @return the next character
		 * @throws ParseException if the cursor is past the end of the string
		 */
		char next() throws ParseException {
			if (next >= sym.length()) {
				throw new ParseException(ParseErrorKind.INVALID);
			}
			return sym.charAt(next++);
		}

		void pushDepth() throws ParseException {
			depth++;
			if (depth > MAX_DEPTH) {
				throw new ParseException(ParseErrorKind.RECURSED_TOO_DEEP);
			}
		}

		void popDepth() {
			depth--;
		}

		/**
		 * Reads a sequence of hexadecimal digits terminated by {@code '_'} and exposes them as a
		 * {@link HexNibbles} helper.
		 * @return the hex nibbles
		 * @throws ParseException if the expected format is not found
		 */
		HexNibbles hexNibbles() throws ParseException {
			int start = next;
			while (true) {
				char c = next();
				if (isHexDigit(c)) {
					continue;
				}
				if (c == '_') {
					break;
				}
				throw new ParseException(ParseErrorKind.INVALID);
			}
			return new HexNibbles(sym.substring(start, next - 1));
		}

		/**
		 * Parses a decimal digit character.
		 * @return the digit
		 * @throws ParseException if the next character is not a digit 
		 */
		int digit10() throws ParseException {
			int p = peek();
			if (p >= '0' && p <= '9') {
				next++;
				return p - '0';
			}
			throw new ParseException(ParseErrorKind.INVALID);
		}

		/**
		 * Parses the next base-62 digit.
		 * @return the digit
		 * @throws ParseException if the next character is not a digit 
		 */
		int digit62() throws ParseException {
			int p = peek();
			if (p >= '0' && p <= '9') {
				next++;
				return p - '0';
			}
			if (p >= 'a' && p <= 'z') {
				next++;
				return 10 + (p - 'a');
			}
			if (p >= 'A' && p <= 'Z') {
				next++;
				return 36 + (p - 'A');
			}
			throw new ParseException(ParseErrorKind.INVALID);
		}

		/**
		 * Reads a base-62 integer terminated by {@code '_'} and returns the decoded value.
		 * @return the integer value
		 * @throws ParseException if no integer value is found
		 */
		long integer62() throws ParseException {
			if (eat('_')) {
				return 0;
			}

			long value = 0;
			while (!eat('_')) {
				int digit = digit62();
				value = multiplyAddBase62(value, digit);
			}
			return addExact(value, 1);
		}

		/**
		 * Optionally consumes a base-62 integer prefixed by {@code tag} and returns the decoded value.
		 * @param tag the tag prefix
		 * @return the integer
		 * @throws ParseException if the incorrect integer value is found 
		 */
		long optInteger62(char tag) throws ParseException {
			if (!eat(tag)) {
				return 0;
			}
			return addExact(integer62(), 1);
		}

		/**
		 * Parses the optional `s` disambiguator used to render hash-like suffixes.
		 * @return the integer value
		 * @throws ParseException if the incorrect integer value is found 
		 */
		long disambiguator() throws ParseException {
			return optInteger62('s');
		}

		/**
		 * Reads the namespace designator that precedes nested paths.
		 * @return the namespace designator
		 * @throws ParseException if no valid designator is found
		 */
		Character namespace() throws ParseException {
			char c = next();
			if (c >= 'A' && c <= 'Z') {
				return Character.valueOf(c);
			}
			if (c >= 'a' && c <= 'z') {
				return null;
			}
			throw new ParseException(ParseErrorKind.INVALID);
		}

		/**
		 * Resolves a backreference, returning a new parser positioned at the referenced start.
		 * @return the parser
		 * @throws ParseException if an incorrect offset value is found 
		 */
		Parser backref() throws ParseException {
			int start = next - 1;
			long offset = integer62();
			if (offset >= start) {
				throw new ParseException(ParseErrorKind.INVALID);
			}
			Parser p = new Parser(sym, (int) offset, depth);
			p.pushDepth();
			return p;
		}

		/**
		 * Parses an identifier, handling punycode (for non-ASCII) and optional disambiguator suffixes.
		 * @return the identifier
		 * @throws ParseException if the incorrect identifier values are found 
		 */
		Ident ident() throws ParseException {
			boolean isPunycode = eat('u');
			int len = digit10();
			if (len != 0) {
				while (true) {
					int peek = peek();
					if (peek < '0' || peek > '9') {
						break;
					}
					next++;
					len = multiplyExact(len, 10);
					len = addExact(len, peek - '0');
				}
			}

			eat('_');

			if (len < 0 || next + len > sym.length()) {
				throw new ParseException(ParseErrorKind.INVALID);
			}
			String raw = sym.substring(next, next + len);
			next += len;

			if (isPunycode) {
				int sep = raw.lastIndexOf('_');
				String ascii;
				String punycode;
				if (sep >= 0) {
					ascii = raw.substring(0, sep);
					punycode = raw.substring(sep + 1);
				}
				else {
					ascii = "";
					punycode = raw;
				}
				if (punycode.isEmpty()) {
					throw new ParseException(ParseErrorKind.INVALID);
				}
				return new Ident(ascii, punycode);
			}

			return new Ident(raw, "");
		}
	}

	/**
	 * Pretty printer that mirrors the upstream rustc-demangle formatter. It consumes parsed
	 * tokens by delegating back into {@link Parser} and emits either the normal or the
	 * alternate (hash-stripped) textual form depending on the {@code alternate} flag.
	 */
	private static final class Printer {
		private Parser parser;
		private StringBuilder out;
		private int boundLifetimeDepth;
		private final boolean alternate;

		Printer(Parser parser, StringBuilder out, boolean alternate) {
			this.parser = parser;
			this.out = out;
			this.boundLifetimeDepth = 0;
			this.alternate = alternate;
		}

		static Parser dryRunParsePath(Parser parser, boolean inValue, boolean alternate)
				throws ParseException {
			Printer printer = new Printer(parser, null, alternate);
			printer.printPath(inValue);
			return printer.parser.copy();
		}

		/**
		 * @return the accumulated demangled output.
		 */
		String finish() {
			return out == null ? "" : out.toString();
		}

		/**
		 * @return any suffix that was not consumed during the primary parse (e.g. ".llvm" decorations).
		 */
		String remaining() {
			return parser.remaining();
		}

		/**
		 * Prints a v0 path grammar node. This mirrors the old implementation's {@code RustPath.parse}.
		 * @param inValue true if in the middle of parsing a value
		 * @throws ParseException if an invalid identifier is encountered
		 */
		void printPath(boolean inValue) throws ParseException {
			parser.pushDepth();

			char tag = parser.next();
			switch (tag) {
				case 'C': { // crate root / plain identifier
					long dis = parser.disambiguator();
					Ident name = parser.ident();
					print(name.render());
					if (dis != 0 && !alternate) {
						print('[');
						printLowerHex(dis);
						print(']');
					}
					break;
				}
				case 'N': { // nested path (module::item)
					Character ns = parser.namespace();
					printPath(inValue);
					long dis = parser.disambiguator();
					Ident name = parser.ident();

					if (ns != null) {
						print("::{");
						switch (ns.charValue()) {
							case 'C':
								print("closure");
								break;
							case 'S':
								print("shim");
								break;
							default:
								print(ns.charValue());
								break;
						}
						if (!name.isEmpty()) {
							print(':');
							print(name.render());
						}
						print('#');
						print(dis);
						print('}');
					}
					else if (!name.isEmpty()) {
						print("::");
						print(name.render());
					}
					break;
				}
				case 'M': // inherent impl path (<impl-path>::item)
				case 'X': // trait impl path (<T as Trait>::item)
				case 'Y': { // trait definition (<T as Trait>)
					if (tag != 'Y') {
						parser.disambiguator();
						skippingPrinting(pr -> pr.printPath(false));
					}
					print('<');
					printType();
					if (tag != 'M') {
						print(" as ");
						printPath(false);
					}
					print('>');
					break;
				}
				case 'I': { // path with generic arguments
					printPath(inValue);
					if (inValue) {
						print("::");
					}
					print('<');
					printSepList(pr -> pr.printGenericArg(), ", ");
					print('>');
					break;
				}
				case 'B': { // backreference into previously seen path
					printBackref(pr -> pr.printPath(inValue));
					break;
				}
				default:
					throw new ParseException(ParseErrorKind.INVALID);
			}

			parser.popDepth();
		}

		/** Prints a single generic argument (lifetime, const, or type). */
		private void printGenericArg() throws ParseException {
			if (parser.eat('L')) {
				long lt = parser.integer62();
				printLifetimeFromIndex(lt);
			}
			else if (parser.eat('K')) {
				printConst(false);
			}
			else {
				printType();
			}
		}

		/** Prints a type node (the equivalent of legacy {@code RustType.parse}). */
		private void printType() throws ParseException {
			char tag = parser.next();
			String basic = basicType(tag);
			if (basic != null) {
				print(basic);
				return;
			}

			parser.pushDepth();

			switch (tag) {
				case 'R': // &T
				case 'Q': { // &mut T
					print('&');
					if (parser.eat('L')) {
						long lt = parser.integer62();
						if (lt != 0) {
							printLifetimeFromIndex(lt);
							print(' ');
						}
					}
					if (tag != 'R') {
						print("mut ");
					}
					printType();
					break;
				}
				case 'P': // *const T
				case 'O': { // *mut T
					print('*');
					if (tag == 'P') {
						print("const ");
					}
					else {
						print("mut ");
					}
					printType();
					break;
				}
				case 'A': // [T; N]
				case 'S': { // [T]
					print('[');
					printType();
					if (tag == 'A') {
						print("; ");
						printConst(true);
					}
					print(']');
					break;
				}
				case 'T': { // tuple (T1, T2, ...)
					print('(');
					int count = printSepList(Printer::printType, ", ");
					if (count == 1) {
						print(',');
					}
					print(')');
					break;
				}
				case 'F': { // fn(...) -> ...
					inBinder(pr -> {
						boolean isUnsafe = pr.parser.eat('U');
						String abi = null;
						if (pr.parser.eat('K')) {
							if (pr.parser.eat('C')) {
								abi = "C";
							}
							else {
								Ident ident = pr.parser.ident();
								if (!ident.punycode.isEmpty() || ident.ascii.isEmpty()) {
									throw new ParseException(ParseErrorKind.INVALID);
								}
								abi = ident.ascii;
							}
						}

						if (isUnsafe) {
							pr.print("unsafe ");
						}

						if (abi != null) {
							pr.print("extern \"");
							String[] parts = abi.split("_");
							for (int i = 0; i < parts.length; i++) {
								if (i != 0) {
									pr.print('-');
								}
								pr.print(parts[i]);
							}
							pr.print("\" ");
						}

						pr.print("fn(");
						pr.printSepList(Printer::printType, ", ");
						pr.print(')');

						if (!pr.parser.eat('u')) {
							pr.print(" -> ");
							pr.printType();
						}
					});
					break;
				}
				case 'D': { // dyn Trait + bounds
					print("dyn ");
					inBinder(pr -> {
						pr.printSepList(Printer::printDynTrait, " + ");
					});
					if (!parser.eat('L')) {
						throw new ParseException(ParseErrorKind.INVALID);
					}
					long lt = parser.integer62();
					if (lt != 0) {
						print(" + ");
						printLifetimeFromIndex(lt);
					}
					break;
				}
				case 'B': { // backref to previously printed type
					printBackref(Printer::printType);
					break;
				}
				case 'W': { // type with pattern (unstable internal form)
					printType();
					print(" is ");
					printPat();
					break;
				}
				default: {
					parser.next--; // rewind for path parsing
					printPath(false);
					break;
				}
			}

			parser.popDepth();
		}

		/**
		 * Prints either a plain path or a path with `<...>` generics, returning whether the caller
		 * should emit the closing `>` (needed for dyn-trait associated bindings).
		 */
		private boolean printPathMaybeOpenGenerics() throws ParseException {
			if (parser.eat('B')) {
				final boolean[] open = new boolean[] { false };
				printBackref(pr -> open[0] = pr.printPathMaybeOpenGenerics());
				return open[0];
			}
			if (parser.eat('I')) {
				printPath(false);
				print('<');
				printSepList(Printer::printGenericArg, ", ");
				return true;
			}
			printPath(false);
			return false;
		}

		/**
		 * Prints a single trait appearing inside a `dyn` object, including associated type bindings.
		 */
		private void printDynTrait() throws ParseException {
			boolean open = printPathMaybeOpenGenerics();
			while (parser.eat('p')) {
				if (!open) {
					print('<');
					open = true;
				}
				else {
					print(", ");
				}
				Ident name = parser.ident();
				print(name.render());
				print(" = ");
				printType();
			}
			if (open) {
				print('>');
			}
		}

		/** Prints pattern fragments used by the unstable `is` syntax (range unions, etc.). */
		private void printPat() throws ParseException {
			char tag = parser.next();
			switch (tag) {
				case 'R':
					printConst(false);
					print("..=");
					printConst(false);
					break;
				case 'O':
					parser.pushDepth();
					printPat();
					while (!parser.eat('E')) {
						print(" | ");
						printPat();
					}
					parser.popDepth();
					break;
				case 'N':
					print("!null");
					break;
				default:
					throw new ParseException(ParseErrorKind.INVALID);
			}
		}

		/** Prints a constant expression appearing either as a value or inside generics. */
		private void printConst(boolean inValue) throws ParseException {
			char tag = parser.next();
			parser.pushDepth();

			boolean openedBrace = false;
			final boolean requireWrap = !inValue;

			switch (tag) {
				case 'p': // `_` placeholder
					print('_');
					break;
				case 'h':
				case 't':
				case 'm':
				case 'y':
				case 'o':
				case 'j': // unsigned integers
					printConstUint(tag);
					break;
				case 'a':
				case 's':
				case 'l':
				case 'x':
				case 'n':
				case 'i': // signed integers
					if (parser.eat('n')) {
						print('-');
					}
					printConstUint(tag);
					break;
				case 'b': { // bool
					Long v = parser.hexNibbles().tryParseUInt();
					if (v == null) {
						throw new ParseException(ParseErrorKind.INVALID);
					}
					if (v == 0) {
						print("false");
					}
					else if (v == 1) {
						print("true");
					}
					else {
						throw new ParseException(ParseErrorKind.INVALID);
					}
					break;
				}
				case 'c': { // char literal
					Long value = parser.hexNibbles().tryParseUInt();
					if (value == null || value < 0 || value > Character.MAX_CODE_POINT) {
						throw new ParseException(ParseErrorKind.INVALID);
					}
					String data = new String(Character.toChars(value.intValue()));
					printQuotedEscapedChars('\'', data);
					break;
				}
				case 'e': { // str literal (stored as *"...")
					if (requireWrap) {
						openedBrace = true;
						print('{');
					}
					print('*');
					printConstStrLiteral();
					break;
				}
				case 'R':
				case 'Q': { // references in const position
					if (tag == 'R' && parser.eat('e')) {
						printConstStrLiteral(true);
					}
					else {
						if (requireWrap) {
							openedBrace = true;
							print('{');
						}
						print('&');
						if (tag != 'R') {
							print("mut ");
						}
						printConst(true);
					}
					break;
				}
				case 'A': { // array literal
					if (requireWrap) {
						openedBrace = true;
						print('{');
					}
					print('[');
					printSepList(pr -> pr.printConst(true), ", ");
					print(']');
					break;
				}
				case 'T': { // tuple literal
					if (requireWrap) {
						openedBrace = true;
						print('{');
					}
					print('(');
					int count = printSepList(pr -> pr.printConst(true), ", ");
					if (count == 1) {
						print(',');
					}
					print(')');
					break;
				}
				case 'V': { // enum/struct literal
					if (requireWrap) {
						openedBrace = true;
						print('{');
					}
					printPath(true);
					char variant = parser.next();
					switch (variant) {
						case 'U':
							break;
						case 'T':
							print('(');
							printSepList(pr -> pr.printConst(true), ", ");
							print(')');
							break;
						case 'S':
							print(" { ");
							printSepList(pr -> {
								pr.parser.disambiguator();
								Ident name = pr.parser.ident();
								pr.print(name.render());
								pr.print(": ");
								pr.printConst(true);
							}, ", ");
							print(" }");
							break;
						default:
							throw new ParseException(ParseErrorKind.INVALID);
					}
					break;
				}
				case 'B': { // backref
					printBackref(pr -> pr.printConst(inValue));
					break;
				}
				default:
					throw new ParseException(ParseErrorKind.INVALID);
			}

			if (openedBrace) {
				print('}');
			}

			parser.popDepth();
		}

		/** Formats a hexadecimal string literal as either {@code "..."} or {@code *"..."}. */
		private void printConstStrLiteral() throws ParseException {
			printConstStrLiteral(false);
		}

		private void printConstStrLiteral(boolean bare) throws ParseException {
			String decoded = parser.hexNibbles().tryParseStr();
			if (decoded == null) {
				throw new ParseException(ParseErrorKind.INVALID);
			}
			if (bare) {
				printQuotedEscapedChars('"', decoded);
			}
			else {
				printQuotedEscapedChars('"', decoded);
			}
		}

		/** Emits an integer literal, appending the suffix when alternate formatting is disabled. */
		private void printConstUint(char tyTag) throws ParseException {
			HexNibbles hex = parser.hexNibbles();
			Long value = hex.tryParseUInt();
			if (value != null) {
				print(value);
			}
			else {
				print("0x");
				print(hex.nibbles);
			}
			String ty = basicType(tyTag);
			if (ty != null && !alternate) {
				print(ty);
			}
		}

		/** Replays a previously printed node referenced by a `B` backref tag. */
		private void printBackref(PrinterConsumer consumer) throws ParseException {
			Parser backref = parser.backref();
			if (out == null) {
				return;
			}
			Parser saved = parser;
			parser = backref;
			consumer.accept(this);
			parser = saved;
		}

		/** Handles the {@code for<...>} binder that introduces late-bound lifetimes. */
		private void inBinder(PrinterConsumer consumer) throws ParseException {
			long count = parser.optInteger62('G');
			if (out == null) {
				consumer.accept(this);
				return;
			}
			if (count > 0) {
				print("for<");
				for (int i = 0; i < count; i++) {
					if (i != 0) {
						print(", ");
					}
					boundLifetimeDepth++;
					printLifetimeFromIndex(1);
				}
				print("> ");
			}
			consumer.accept(this);
			boundLifetimeDepth -= (int) count;
		}

		/** Utility for comma-separated lists terminated by {@code 'E'}. */
		private int printSepList(PrinterConsumer consumer, String sep) throws ParseException {
			int count = 0;
			while (!parser.eat('E')) {
				if (count != 0) {
					print(sep);
				}
				consumer.accept(this);
				count++;
			}
			return count;
		}

		/** Converts the encoded lifetime index into a textual representation (e.g. {@code 'a}). */
		private void printLifetimeFromIndex(long lt) throws ParseException {
			if (out == null) {
				return;
			}
			print('\'');
			if (lt == 0) {
				print('_');
				return;
			}
			long depth = boundLifetimeDepth - lt;
			if (depth < 0) {
				throw new ParseException(ParseErrorKind.INVALID);
			}
			if (depth < 26) {
				print((char) ('a' + depth));
			}
			else {
				print('_');
				print(depth);
			}
		}

		/** Temporarily disables output while still consuming the parse tree (used for impl paths). */
		private void skippingPrinting(PrinterConsumer consumer) throws ParseException {
			StringBuilder original = out;
			out = null;
			consumer.accept(this);
			out = original;
		}

		private void print(String text) {
			if (out != null) {
				out.append(text);
			}
		}

		private void print(char c) {
			if (out != null) {
				out.append(c);
			}
		}

		private void print(long value) {
			if (out != null) {
				out.append(value);
			}
		}

		private void printLowerHex(long value) {
			if (out != null) {
				out.append(Long.toHexString(value));
			}
		}

		private void printQuotedEscapedChars(char quote, String data) {
			if (out == null) {
				return;
			}
			out.append(quote);
			data.codePoints().forEach(cp -> {
				if ((quote == '\'' && cp == '"') || (quote == '"' && cp == '\'')) {
					out.appendCodePoint(cp);
					return;
				}
				switch (cp) {
					case '\\':
						out.append("\\\\");
						break;
					case '\n':
						out.append("\\n");
						break;
					case '\r':
						out.append("\\r");
						break;
					case '\t':
						out.append("\\t");
						break;
					case '\0':
						out.append("\\0");
						break;
					case '"':
						if (quote == '"') {
							out.append("\\\"");
						}
						else {
							out.append('"');
						}
						break;
					case '\'':
						if (quote == '\'') {
							out.append("\\'");
						}
						else {
							out.append('\'');
						}
						break;
					default:
						if (cp < 0x20 || cp == 0x7f) {
							out.append(String.format("\\x%02x", cp));
						}
						else {
							out.appendCodePoint(cp);
						}
				}
			});
			out.append(quote);
		}
	}

	@FunctionalInterface
	private interface PrinterConsumer {
		void accept(Printer printer) throws ParseException;
	}

	private static final class Ident {
		private final String ascii;
		private final String punycode;

		Ident(String ascii, String punycode) {
			this.ascii = ascii;
			this.punycode = punycode;
		}

		boolean isEmpty() {
			return ascii.isEmpty() && punycode.isEmpty();
		}

		String render() {
			if (punycode.isEmpty()) {
				return ascii;
			}

			List<Integer> decoded = decodePunycode();
			if (decoded == null) {
				StringBuilder builder = new StringBuilder("punycode{");
				if (!ascii.isEmpty()) {
					builder.append(ascii).append('-');
				}
				builder.append(punycode).append('}');
				return builder.toString();
			}

			StringBuilder out = new StringBuilder();
			for (int cp : decoded) {
				out.appendCodePoint(cp);
			}
			return out.toString();
		}

		/**
		 * Decodes the punycode payload used for non-ASCII identifiers. Returns {@code null} when the
		 * sequence is malformed so callers can fall back to the `{punycode{...}}` representation.
		 */
		private List<Integer> decodePunycode() {
			if (punycode.isEmpty()) {
				return null;
			}

			List<Integer> output = new ArrayList<>();
			ascii.codePoints().forEach(cp -> output.add(cp));

			int base = 36;
			int tMin = 1;
			int tMax = 26;
			int skew = 38;
			int damp = 700;
			int bias = 72;
			long i = 0;
			long n = 0x80;
			int index = 0;

			while (index < punycode.length()) {
				long delta = 0;
				long w = 1;
				int k = base;
				while (true) {
					if (index >= punycode.length()) {
						return null;
					}
					char c = punycode.charAt(index++);
					int digit;
					if (c >= 'a' && c <= 'z') {
						digit = c - 'a';
					}
					else if (c >= '0' && c <= '9') {
						digit = 26 + (c - '0');
					}
					else {
						return null;
					}

					try {
						delta = addExact(delta, multiplyExact(w, digit));
					}
					catch (ParseException e) {
						return null;
					}
					int t = clamp(k - bias, tMin, tMax);
					if (digit < t) {
						break;
					}
					try {
						w = multiplyExact(w, base - t);
					}
					catch (ParseException e) {
						return null;
					}
					k += base;
				}

				int outLen = output.size() + 1;
				try {
					i = addExact(i, delta);
					n = addExact(n, i / outLen);
				}
				catch (ParseException e) {
					return null;
				}
				i %= outLen;

				if (!Character.isValidCodePoint((int) n) || i > Integer.MAX_VALUE) {
					return null;
				}
				output.add((int) i, (int) n);
				i++;

				delta /= damp;
				damp = 2;
				delta += delta / outLen;
				int kAdjust = 0;
				while (delta > ((base - tMin) * (long) tMax) / 2) {
					delta /= (base - tMin);
					kAdjust += base;
				}
				bias = kAdjust + (int) (((base - tMin + 1L) * delta) / (delta + skew));
			}

			return output;
		}
	}

	private static final class HexNibbles {
		private final String nibbles;

		HexNibbles(String nibbles) {
			this.nibbles = nibbles;
		}

		Long tryParseUInt() {
			String trimmed = stripLeadingZeros(nibbles);
			if (trimmed.length() > 16) {
				return null;
			}
			long value = 0;
			for (int i = 0; i < trimmed.length(); i++) {
				int digit = hexValue(trimmed.charAt(i));
				value = (value << 4) | digit;
			}
			return Long.valueOf(value);
		}

		String tryParseStr() {
			if ((nibbles.length() & 1) != 0) {
				return null;
			}
			byte[] bytes = new byte[nibbles.length() / 2];
			for (int i = 0; i < bytes.length; i++) {
				int hi = hexValue(nibbles.charAt(2 * i));
				int lo = hexValue(nibbles.charAt(2 * i + 1));
				bytes[i] = (byte) ((hi << 4) | lo);
			}
			try {
				return StandardCharsets.UTF_8.newDecoder()
						.decode(ByteBuffer.wrap(bytes))
						.toString();
			}
			catch (CharacterCodingException e) {
				return null;
			}
		}
	}

	/**
	 * Maps the single-character primitive tags to their textual forms (e.g. {@code 'a'} =&gt; {@code i8}).
	 * The ordering matches the original implementation to ease diffing against upstream rustc-demangle.
	 */
	private static String basicType(char tag) {
		switch (tag) {
			case 'a':
				return "i8";
			case 'b':
				return "bool";
			case 'c':
				return "char";
			case 'd':
				return "f64";
			case 'e':
				return "str";
			case 'f':
				return "f32";
			case 'h':
				return "u8";
			case 'i':
				return "isize";
			case 'j':
				return "usize";
			case 'l':
				return "i32";
			case 'm':
				return "u32";
			case 'n':
				return "i128";
			case 'o':
				return "u128";
			case 'p':
				return "_";
			case 's':
				return "i16";
			case 't':
				return "u16";
			case 'u':
				return "()";
			case 'v':
				return "...";
			case 'x':
				return "i64";
			case 'y':
				return "u64";
			case 'z':
				return "!";
			default:
				return null;
		}
	}

	/**
	 * Utility used by the punycode decoder to mimic rustc's bias adjustment logic.
	 */
	private static int clamp(int value, int min, int max) {
		if (value < min) {
			return min;
		}
		if (value > max) {
			return max;
		}
		return value;
	}

	/**
	 * Parses a single hexadecimal nibble character.
	 */
	private static int hexValue(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'a' && c <= 'f') {
			return 10 + (c - 'a');
		}
		if (c >= 'A' && c <= 'F') {
			return 10 + (c - 'A');
		}
		throw new IllegalArgumentException("invalid hex digit: " + c);
	}

	private static String stripLeadingZeros(String value) {
		int i = 0;
		while (i < value.length() && value.charAt(i) == '0') {
			i++;
		}
		return value.substring(i);
	}

	private static boolean isHexDigit(char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
	}

	private static long multiplyExact(long a, long b) throws ParseException {
		if (a == 0 || b == 0) {
			return 0;
		}
		long result = a * b;
		if (Long.divideUnsigned(result, a) != b) {
			throw new ParseException(ParseErrorKind.INVALID);
		}
		return result;
	}

	private static long multiplyAddBase62(long value, int digit) throws ParseException {
		long mult = multiplyExact(value, 62);
		return addExact(mult, digit);
	}

	private static int multiplyExact(int a, int b) throws ParseException {
		try {
			return Math.multiplyExact(a, b);
		}
		catch (ArithmeticException e) {
			throw new ParseException(ParseErrorKind.INVALID);
		}
	}

	private static long addExact(long a, long b) throws ParseException {
		long result = a + b;
		if (Long.compareUnsigned(result, a) < 0) {
			throw new ParseException(ParseErrorKind.INVALID);
		}
		return result;
	}

	private static int addExact(int a, int b) throws ParseException {
		try {
			return Math.addExact(a, b);
		}
		catch (ArithmeticException e) {
			throw new ParseException(ParseErrorKind.INVALID);
		}
	}
}
