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
package ghidra.app.plugin.core.analysis.rust.demangler;

import java.net.IDN;
import java.util.*;

/**
 * A class that will demangle Rust symbols mangled according to the V0 format. This class
 * implements the grammar that will translate a mangled string into a demangled one.
 * Documentation is {@link "https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html"} here.
 */
public class RustDemanglerV0 {

	/**
	 * Demangles a symbol according to the format
	 * @param symbol the mangled symbol name
	 * @return the demangled symbol name
	 */
	public static String demangle(String symbol) {
		if (symbol.startsWith("_R")) {
			symbol = symbol.substring(2);
		}
		else if (symbol.startsWith("R")) {
			symbol = symbol.substring(1);
		}
		else if (symbol.startsWith("__R")) {
			symbol = symbol.substring(3);
		}

		if (!symbol.matches("\\A\\p{ASCII}*\\z")) {
			return null;
		}

		Symbol cursor = new Symbol(symbol);

		return RustPath.parse(cursor).toString();
	}
}

/**
 * A class that represents a symbol in the demangling process. It keeps track of
 * the current state of the symbol and implements various methods to assist with
 * demangling it.
 */
class Symbol {
	/** A list of backref objects */
	Map<Integer, SymbolNode> backrefs = new HashMap<Integer, SymbolNode>();

	/** The mangled symbol */
	String mangled;

	/** The current position in the mangled symbol */
	int pos = 0;

	/**
	 * Creates a symbol object
	 * @param mangled the mangled symbol name
	 */
	public Symbol(String mangled) {
		this.mangled = mangled;
	}

	/**
	 * Adds a backref to the list
	 * @param index the index of the backref
	 * @param value the backref object to add
	 */
	public void backrefAdd(int index, SymbolNode value) {
		backrefs.put(Integer.valueOf(index), value);
		index += 1;
	}

	/**
	 * Gets the backref at a certain index
	 * @param index the index of he backref to return
	 * @return the backref object
	 */
	public String getBackref(int index) {
		SymbolNode backref = backrefs.get(index);
		if (backref != null) {
			return backref.toString();
		}

		return "{backref " + index + "}";
	}

	/**
	 * Returns the number of the encoded backref
	 * @return the number sting
	 */
	public String parseBackref() {
		if (stripPrefix('B')) {
			return parseBase62Number();
		}

		return null;
	}

	/**
	 * Returns the remaining string to be demangled
	 * @return the mangled string
	 */
	public String remaining() {
		return mangled.substring(pos);
	}

	/**
	 * Strips the first char of the mangled string if it's equal to the argument
	 * @param c the char to strip
	 * @return if the strip succeeded
	 */
	public boolean stripPrefix(char c) {
		if (c == nextChar()) {
			popChar();
			return true;
		}

		return false;
	}

	/**
	 * Gets the next char in the mangled string
	 * @return the next char
	 */
	public char nextChar() {
		return mangled.charAt(pos);
	}

	/**
	 * Gets the next int in the mangled string
	 * @return the next int
	 */
	public int nextInt() {
		return mangled.charAt(pos);
	}

	/**
	 * Pops the next char in the mangled string
	 * @return the next char
	 */
	public char popChar() {
		char c = mangled.charAt(pos);
		pos += 1;
		return c;
	}

	/**
	 * Parses the following numerical digits in the mangled sting
	 * @return the parsed integer
	 */
	public int parseDigits() {
		String num = "";

		if (nextChar() == '0') {
			return 0;
		}

		while (nextChar() >= '0' && nextChar() <= '9') {
			num += popChar();
		}

		return Integer.parseInt(num);
	}

	/**
	 * Parses the string until the passed char is reached
	 * @param c the char to parse until
	 * @return the parsed string
	 */
	public String parseUntil(char c) {
		String data = "";

		while (nextChar() != c) {
			data += popChar();
		}

		return data;
	}

	/**
	 * Subtracts one from the position in the mangled string
	 */
	public void backChar() {
		pos -= 1;
	}

	/**
	 * Parses the 
	 * @param n number of characters
	 * @return the parsed string
	 */
	public String parseString(int n) {
		String s = mangled.substring(pos, pos + n);
		pos += n;
		return s;
	}

	/**
	 * Returns if the end of the mangled string has been reached
	 * @return if the end has been reached
	 */
	public boolean isEmpty() {
		return mangled.length() <= pos;
	}

	/**
	 * Parses the following base 62 number
	 * @return the parsed num string
	 */
	public String parseBase62Number() {
		String numString = parseUntil('_');
		popChar();
		return numString;
	}
}

/**
 * A node to be used in symbol parsing
 */
interface SymbolNode {
	// Parent class
}

/**
 * A class to represent a nested path node
 */
class RustPathNested implements SymbolNode {
	SymbolNode parent;
	RustIdentifier identifier;

	public RustPathNested(SymbolNode parent, RustIdentifier identifier) {
		this.parent = parent;
		this.identifier = identifier;
	}

	@Override
	public String toString() {
		return parent.toString() + "::" + identifier.toString();
	}
}

/**
 * A class to represent a string node
 */
class RustString implements SymbolNode {
	String data;

	public RustString(String data) {
		this.data = data;
	}

	@Override
	public String toString() {
		return data;
	}
}

/** 
 * A class that will represent and parse a backref node
 */
class RustBackref implements SymbolNode {
	int backref;
	Symbol s;

	public RustBackref(int backref, Symbol s) {
		this.backref = backref;
		this.s = s;
	}

	@Override
	public String toString() {
		return s.getBackref(backref);
	}
}

/**
 * A class to represent and parse a rust symbol path node
 */
class RustPath implements SymbolNode {
	SymbolNode child;

	public RustPath(SymbolNode child) {
		this.child = child;
	}

	public RustPath(String child) {
		this.child = new RustString(child);
	}

	/**
	 * Parses a rust path from a mangled symbol
	 * @param s parse the rust path
	 * @return the rust path object
	 */
	public static RustPath parse(Symbol s) {
		int pos = s.pos - 1;

		if (s.nextChar() == 'B') {
			String backref = s.parseBackref();
			int i = Integer.parseInt(backref, 16);
			RustBackref b = new RustBackref(i, s);
			RustPath path = new RustPath(b);
			return path;
		}

		char c = s.popChar();
		if (c == 'C') {
			// Crate root?
			RustIdentifier identifier = RustIdentifier.parse(s, new RustNamespace("crate"));
			s.backrefAdd(pos, identifier);
			return new RustPath(identifier.toString());
		}
		else if (c == 'M') {
			RustImplPath implPath = RustImplPath.parse(s);
			RustType type = RustType.parse(s);
			RustPath path = new RustPath("<" + implPath + "::" + type + ">");

			s.backrefAdd(pos, path);
			return path;
			// <impl-path> <type>
			// <T> (inherent impl)
		}
		else if (c == 'X') {
			RustImplPath.parse(s);
			RustType type = RustType.parse(s);
			RustPath parent = RustPath.parse(s);
			RustPath path = new RustPath("<" + type + " as " + parent + ">");
			s.backrefAdd(pos, path);
			return path;
			// <impl-path> <type> <data>
			// <T as Trait> (trait impl)
		}
		else if (c == 'Y') {
			RustType type = RustType.parse(s);
			RustPath parent = RustPath.parse(s);

			RustPath path = new RustPath("<" + type + " as " + parent + ">");
			s.backrefAdd(pos, path);
			return path;
			// <type> <data>
			// <T as Trait> (trait definition)
		}
		else if (c == 'N') {
			RustNamespace namespace = RustNamespace.parse(s);
			RustPath parent = RustPath.parse(s);
			RustIdentifier id = RustIdentifier.parse(s, namespace);
			RustPathNested nested = new RustPathNested(parent, id);

			RustPath path = new RustPath(nested.toString());
			s.backrefAdd(pos, path);
			return path;
		}
		else if (c == 'I') {
			RustPath parent = RustPath.parse(s);
			RustGenericArgs args = RustGenericArgs.parse(s);

			if (args == null) {
				RustPath path = new RustPath(parent);
				s.backrefAdd(pos, path);
				return path;
			}

			RustPath path = new RustPath("" + parent + args);
			s.backrefAdd(pos, path);
			return path;
		}
		else if (c == 'B') {
			s.backChar();
			String b = s.parseBackref();
			int i = Integer.parseInt(b, 16);
			RustBackref br = new RustBackref(i, s);
			return new RustPath(br);
		}

		return null;
	}

	@Override
	public String toString() {
		return child.toString();
	}
}

/**
 * Parses and represents a rust symbol namespace node
 */
class RustNamespace {
	String data;

	public RustNamespace(String data) {
		this.data = data;
	}

	/**
	 * Parses a rust namespace from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust path object
	 */
	public static RustNamespace parse(Symbol s) {
		char c = s.popChar();

		if (c == 'C') {
			// closure
			return new RustNamespace("{closure}");
		}
		else if (c == 'S') {
			// shim
			return new RustNamespace("{shim}");
		}
		else if (c >= 'A' && c <= 'Z') {
			// other special namespaces
			return new RustNamespace(String.valueOf(c));
		}
		else if (c >= 'a' && c <= 'z') {
			// internal namespaces
			return new RustNamespace(String.valueOf(c));
		}

		return null;
	}

	@Override
	public String toString() {
		return data;
	}
}

/**
 * Parses and represents a rust symbol impl path node
 */
class RustImplPath implements SymbolNode {
	RustPath path;
	RustString disambiguator;

	public RustImplPath(RustPath path, RustString disambiguator) {
		this.path = path;
		this.disambiguator = disambiguator;
	}

	/**
	 * Parses a impl rust path from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust impl path object
	 */
	public static RustImplPath parse(Symbol s) {
		RustString disambiguator = null;
		if (s.nextChar() == 's') {
			disambiguator = RustIdentifier.parseDisambiguator(s);
		}

		RustPath path = RustPath.parse(s);

		return new RustImplPath(path, disambiguator);
	}

	@Override
	public String toString() {
		String s = path.toString();

		if (disambiguator != null && disambiguator.toString() != "") {
			s += "::" + "[" + disambiguator.toString() + "]";
		}

		return s;
	}
}

/**
 * Parses and represents an rust symbol identifier
 */
class RustIdentifier implements SymbolNode {
	String id;
	RustNamespace namespace;
	RustString disambiguator;

	public RustIdentifier(RustNamespace namespace, String id, RustString disambiguator) {
		this.id = id;
		this.namespace = namespace;
		this.disambiguator = disambiguator;
	}

	/**
	 * Parses a rust identifier from a mangled symbol
	 * @param s symbol to parse
	 * @param namespace namespace of symbol
	 * @return the rust identifier object
	 */
	public static RustIdentifier parse(Symbol s, RustNamespace namespace) {
		RustString disambiguator = null;

		if (s.nextChar() == 's') {
			disambiguator = parseDisambiguator(s);
		}

		String id = parseUndisambiguatedIdentifier(s);
		return new RustIdentifier(namespace, id, disambiguator);
	}

	/**
	 * Parses a rust disambiguator from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the disambiguator
	 */
	public static RustString parseDisambiguator(Symbol s) {
		char c = s.popChar();
		assert c == 's';
		return new RustString(s.parseBase62Number());
	}

	/**
	 * Parses a rust undisambiguated identifier from a mangled symbol
	 * @param s symbol to parse
	 * @return the corresponding string object
	 */
	public static String parseUndisambiguatedIdentifier(Symbol s) {
		boolean punycode = s.stripPrefix('u');
		int num = s.parseDigits();

		if (s.nextChar() == '_') {
			s.popChar();
		}

		if (num == 0) {
			char c = s.popChar();
			return "{closure#" + c + "}";
		}

		String bytes = s.parseString(num);

		if (punycode) {
			return IDN.toASCII(bytes, IDN.ALLOW_UNASSIGNED);
		}

		return bytes;
	}

	@Override
	public String toString() {
		return id.toString();
	}
}

/**
 * Parses and represents rust generic arguments
 */
class RustGenericArgs implements SymbolNode {
	ArrayList<RustGenericArg> args;

	public RustGenericArgs(ArrayList<RustGenericArg> args) {
		this.args = args;
	}

	/**
	 * Parses generics arguments from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust generic arguments object
	 */
	public static RustGenericArgs parse(Symbol s) {
		ArrayList<RustGenericArg> genericArgs = new ArrayList<RustGenericArg>();

		while (s.nextChar() != 'E') {
			RustGenericArg arg = RustGenericArg.parse(s);
			if (arg == null) {
				return null;
			}

			genericArgs.add(arg);
		}

		s.popChar();

		return new RustGenericArgs(genericArgs);
	}

	@Override
	public String toString() {
		String s = "";

		for (RustGenericArg arg : args) {
			s += arg.toString() + ", ";
		}

		return "<" + s.substring(0, s.length() - 2) + ">";
	}
}

/**
 * Parses and represents a generic argument node in a rust symbol
 */
class RustGenericArg implements SymbolNode {
	SymbolNode child;

	public RustGenericArg(SymbolNode child) {
		this.child = child;
	}

	/**
	 * Parses a rust generic argument from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust generic argument object
	 */
	public static RustGenericArg parse(Symbol s) {
		SymbolNode lifetime = RustLifetime.parse(s);
		if (lifetime != null) {
			return new RustGenericArg(lifetime);
		}

		if (s.nextChar() == 'K') {
			s.popChar();
			SymbolNode constant = RustConst.parse(s);
			if (constant != null) {
				return new RustGenericArg(constant);
			}
		}

		SymbolNode type = RustType.parse(s);
		if (type != null) {
			return new RustGenericArg(type);
		}

		return null;
	}

	@Override
	public String toString() {
		return child.toString();
	}
}

/**
 * Parses a rust lifetime from a mangled symbol
 */
class RustLifetime implements SymbolNode {
	String num;

	public RustLifetime(String num) {
		this.num = num;
	}

	/**
	 * Parses a rust lifetime node from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust lifetime node
	 */
	public static SymbolNode parse(Symbol s) {
		if (s.nextChar() != 'L') {
			return null;
		}

		s.popChar();

		String num = s.parseBase62Number();
		if (num != null) {
			return new RustLifetime(num);
		}

		return null;
	}

	@Override
	public String toString() {
		return num;
	}
}

/**
 * Parses and represents a rust symbol type node
 */
class RustType implements SymbolNode {
	String typeName;
	RustPath path;

	public RustType(String typeName) {
		this.typeName = typeName;
	}

	public RustType(RustPath path) {
		this.path = path;
	}

	/**
	 * Parses a rust type from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust type object
	 */
	public static RustType parse(Symbol s) {
		char c = s.popChar();

		switch (c) {
			case 'a':
				return new RustType("i8");
			case 'b':
				return new RustType("bool");
			case 'c':
				return new RustType("char");
			case 'd':
				return new RustType("f64");
			case 'e':
				return new RustType("str");
			case 'f':
				return new RustType("f32");
			case 'h':
				return new RustType("u8");
			case 'i':
				return new RustType("isize");
			case 'j':
				return new RustType("usize");
			case 'l':
				return new RustType("i32");
			case 'm':
				return new RustType("u32");
			case 'n':
				return new RustType("i128");
			case 'o':
				return new RustType("u128");
			case 's':
				return new RustType("i16");
			case 't':
				return new RustType("u16");
			case 'u':
				return new RustType("()");
			case 'v':
				return new RustType("...");
			case 'x':
				return new RustType("i64");
			case 'y':
				return new RustType("u64");
			case 'z':
				return new RustType("!");
			case 'p':
				return new RustType("_");
			default:
				switch (c) {
					case 'A': // Array sized
						RustType rustType = RustType.parse(s);
						RustConst constant = RustConst.parse(s);
						return new RustType(
							"[" + rustType.toString() + "; " + constant.toString() + "]");
					case 'S': // Array unsized
						SymbolNode symbolType = RustType.parse(s);
						return new RustType("[" + symbolType.toString() + "]");
					case 'T': // Tuple
						ArrayList<String> types = new ArrayList<String>();

						while (s.nextChar() != 'E') {
							SymbolNode symbolNode = RustType.parse(s);
							if (symbolNode != null) {
								types.add(symbolNode.toString());
							}
							else {
								return null; // null type in parse
							}
						}

						s.popChar();

						String type = "(" + String.join(", ", types) + ")";
						return new RustType(type);
					case 'R': // &T
						RustLifetime.parse(s);
						SymbolNode type1 = RustType.parse(s);
						return new RustType("&" + type1);
					case 'Q': // &mut T
						RustLifetime.parse(s);
						SymbolNode type2 = RustType.parse(s);
						return new RustType("&mut " + type2);
					case 'P': // *const T
						SymbolNode type3 = RustType.parse(s);
						return new RustType("*const " + type3);
					case 'O': // *mut T
						SymbolNode type4 = RustType.parse(s);
						return new RustType("*mut " + type4);
					case 'F': // fn(...) -> ...
						// TODO: FnSig type
					case 'D': // dyn Trait<Assoc = X> + Send + 'a
						String bounds = parseDynBounds(s);
						RustLifetime.parse(s);
						String data = "dyn Trait<Assoc = X>";

						if (bounds != null) {
							data += bounds;
						}

						return new RustType(data);
					case 'B':
						s.backChar();
						String b1 = s.parseBackref();
						int b2 = Integer.parseInt(b1);
						RustBackref b3 = new RustBackref(b2, s);
						return new RustType(new RustPath(b3));
					default:
						s.backChar();
						RustPath path = RustPath.parse(s);
						return new RustType(path);
				}
		}
	}

	/**
	 * Parses a rust dyn bounds from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the dyn bounds
	 */
	public static String parseDynBounds(Symbol s) {
		ArrayList<String> traits = new ArrayList<String>();
		@SuppressWarnings("unused")
		String binder = parseBinder(s);

		while (s.nextChar() != 'E') {
			String trait = parseDynTrait(s);
			traits.add(trait);
		}

		s.popChar();

		return " + " + String.join(" + ", traits);
	}

	/**
	 * Parses a rust dyn trait from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the dyn trait
	 */
	public static String parseDynTrait(Symbol s) {
		RustPath path = RustPath.parse(s);
		@SuppressWarnings("unused")
		String bindings = "";
		while (s.nextChar() == 'p') {
			String binding = parseDynTraitAssocBinding(s);
			bindings += binding;
		}

		if (path == null) {
			return "";
		}

		return path.toString();
	}

	/**
	 * Parses a rust dyn trait associated binding from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the dyn trait associated binding
	 */
	public static String parseDynTraitAssocBinding(Symbol s) {
		s.popChar();

		RustIdentifier.parseUndisambiguatedIdentifier(s);
		SymbolNode type = RustType.parse(s);

		return "dyn " + type.toString();
	}

	/**
	 * Parses a rust binding from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the binding
	 */
	public static String parseBinder(Symbol s) {
		if (s.nextChar() != 'G') {
			return null;
		}

		s.popChar();
		return s.parseBase62Number();
	}

	@Override
	public String toString() {
		if (path != null) {
			return path.toString();
		}

		return typeName;
	}
}

/**
 * Parses and represents a a rust symbol const node
 */
class RustConst implements SymbolNode {
	String name;

	public RustConst(String name) {
		this.name = name;
	}

	/**
	 * Parses a rust const from a mangled symbol
	 * @param s symbol to parse
	 * @return the rust const object
	 */
	public static RustConst parse(Symbol s) {
		SymbolNode type = RustType.parse(s);
		String constData = RustConst.parseConstData(s);

		return new RustConst(constData + type.toString());
	}

	/**
	 * Parses a rust const data from a mangled symbol
	 * @param s symbol to parse
	 * @return a string representing the const data
	 */
	public static String parseConstData(Symbol s) {
		if (s.nextChar() == 'n') {
			s.popChar();
		}

		String name = s.parseUntil('_');
		s.popChar();

		return name;
	}

	@Override
	public String toString() {
		return name;
	}
}
