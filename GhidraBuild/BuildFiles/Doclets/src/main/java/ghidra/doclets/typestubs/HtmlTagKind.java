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

import java.util.HashMap;
import java.util.Map;

import com.sun.source.doctree.EndElementTree;
import com.sun.source.doctree.StartElementTree;

public enum HtmlTagKind {
	// This would be much simpler if we didn't have to handle malformed html
	// HTML container tags REQUIRE a closing tag
	// Unfortunately they are often ommitted, even in the JDK API, which makes
	// this much more complicated then it needs to be.
	// Best we can do it try not to consume elements that can't possibly be ours,
	// log it when encountered and then hope the result isn't ruined.

	A,
	B,
	BIG,
	BLOCKQUOTE {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return kind == this;
		}
	},
	BR,
	CAPTION,
	CITE,
	CODE,
	DD {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case DD, DT, DL -> true;
				default -> false;
			};
		}
	},
	DEL,
	DFN,
	DIV,
	DL {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case DL -> true;
				default -> false;
			};
		}
	},
	DT {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case DD, DT, DL -> true;
				default -> false;
			};
		}
	},
	EM,
	H1 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	H2 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	H3 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	H4 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	H5 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	H6 {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			if (isInline(kind)) {
				return false;
			}
			return switch (kind) {
				case A -> false;
				default -> true;
			};
		}
	},
	HR,
	I,
	IMG,
	INS,
	LI {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case LI -> true;
				default -> false;
			};
		}

		@Override
		public boolean isTerminateBy(EndElementTree end) {
			return switch (getKind(end)) {
				case OL, UL -> true;
				default -> false;
			};
		}
	},
	OL {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return false;
		}
	},
	P,
	PRE {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return false;
		}
	},
	SMALL,
	SPAN,
	STRONG,
	SUB,
	SUP,
	TABLE {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			// no nested tables
			return kind == this;
		}
	},
	TBODY {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case THEAD, TFOOT, TBODY, TABLE -> true;
				default -> false;
			};
		}
	},
	TD {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case TD, TH, TR, THEAD, TFOOT, TBODY, TABLE -> true;
				default -> false;
			};
		}
	},
	TFOOT {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case THEAD, TFOOT, TBODY, TABLE -> true;
				default -> false;
			};
		}
	},
	TH {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case TD, TH, TR, THEAD, TFOOT, TBODY, TABLE -> true;
				default -> false;
			};
		}
	},
	THEAD {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case THEAD, TFOOT, TBODY, TABLE -> true;
				default -> false;
			};
		}
	},
	TR {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return switch (kind) {
				case TR, TABLE, THEAD, TFOOT, TBODY -> true;
				default -> false;
			};
		}
	},
	TT,
	U,
	UL {
		@Override
		boolean isTerminateBy(HtmlTagKind kind) {
			return false;
		}
	},
	VAR,
	UNSUPPORTED;

	private static final Map<String, HtmlTagKind> LOOKUP;

	static {
		HtmlTagKind[] values = values();
		LOOKUP = new HashMap<>(values.length);
		for (HtmlTagKind value : values) {
			LOOKUP.put(value.name(), value);
		}
	}

	/**
	 * Gets the HtmlTagKind with the provided name
	 *
	 * @param name the name
	 * @return the HtmlTagKind with the same name or UNSUPPORTED
	 */
	static HtmlTagKind getKind(String name) {
		return LOOKUP.getOrDefault(name, UNSUPPORTED);
	}

	/**
	 * Gets the HtmlTagKind for the provided element
	 *
	 * @param tag the tag
	 * @return the HtmlTagKind for the provided tag or UNSUPPORTED
	 */
	static HtmlTagKind getKind(StartElementTree tag) {
		return getKind(tag.getName().toString().toUpperCase());
	}

	/**
	 * Gets the HtmlTagKind for the provided element
	 *
	 * @param tag the tag
	 * @return the HtmlTagKind for the provided tag or UNSUPPORTED
	 */
	static HtmlTagKind getKind(EndElementTree tag) {
		return getKind(tag.getName().toString().toUpperCase());
	}

	/**
	 * Checks if this tag is terminated by another tag because it can't possibly contain it
	 *
	 * @param kind the other HtmlTagKind
	 * @return true if this tag canot possibly contain the other kind
	 */
	boolean isTerminateBy(HtmlTagKind kind) {
		return !isInline(kind);
	}

	/**
	 * Checks if this tag is terminated by another element because it can't possibly contain it
	 *
	 * @param kind the other HtmlTagKind
	 * @return true if this tag canot possibly contain the other element
	 */
	public final boolean isTerminateBy(StartElementTree start) {
		HtmlTagKind kind = getKind(start);
		return isTerminateBy(kind);
	}

	/**
	 * Checks if this tag is terminated by the closing another element.<p/>
	 *
	 * This is usually because the other element would contain it.
	 *
	 * @param kind the other HtmlTagKind
	 * @return true if this tag canot possibly contain the other kind
	 */
	public boolean isTerminateBy(EndElementTree end) {
		HtmlTagKind kind = getKind(end);
		if (kind == this) {
			// this tag may not be for the current node so we return false here
			return false;
		}
		return isTerminateBy(kind);
	}

	/**
	 * Checks if the provided tag is a void or empty tag
	 *
	 * @param kind the tag kind
	 * @return true if this is a void or empty tag
	 */
	public static boolean isVoidTag(HtmlTagKind kind) {
		// technically <p> is NOT a void tag
		// unfortunately it is misused so often that the errors/warnings
		// would become junk because the <p> tags would have consumed too much
		return switch (kind) {
			case BR, HR, P -> true;
			default -> false;
		};
	}

	/**
	 * Checks if the provided tag is for inline markup
	 *
	 * @param kind the tag kind
	 * @return true if this kind is for inline markup
	 */
	public static boolean isInline(HtmlTagKind kind) {
		return switch (kind) {
			case B, BIG, CITE, DFN, CODE, DEL, EM, I, INS -> true;
			case SMALL, STRONG, SUB, SUP, TT, U, VAR -> true;
			default -> false;
		};
	}
}
