tree grammar SleighCompiler;

options {
	ASTLabelType=CommonTree;
	tokenVocab=SleighLexer;
}

scope Jump {
	boolean indirect;
}

scope Return {
	boolean noReturn;
}

scope Block {
	ConstructTpl ct;
}

@header {
	import generic.stl.Pair;
	import generic.stl.VectorSTL;
	import ghidra.pcodeCPort.context.SleighError;
	import ghidra.pcodeCPort.opcodes.OpCode;
	import ghidra.pcodeCPort.semantics.*;
	import ghidra.pcodeCPort.slgh_compile.*;
	import ghidra.pcodeCPort.slghpatexpress.*;
	import ghidra.pcodeCPort.slghsymbol.*;
	import ghidra.pcodeCPort.space.AddrSpace;

	import java.math.BigInteger;
	import java.util.Stack;

	import org.antlr.runtime.*;
	import org.antlr.runtime.Token;
	import org.antlr.runtime.tree.*;
}

@members {
	private ParsingEnvironment env = null;
	private SleighCompile sc = null;
	private PcodeCompile pcode = null;

	private void reportError(Location loc, String msg) {
		if (pcode != null) {
	    	pcode.reportError(loc, msg);
	    }
	    else {
	    	sc.reportError(loc, msg);
	    }
	}

	private void reportWarning(Location loc, String msg) {
		if (pcode != null) {
	    	pcode.reportWarning(loc, msg);
	    }
	    else {
	    	sc.reportWarning(loc, msg);
	    }
	}

	private void check(RadixBigInteger rbi) {
		if (rbi.bitLength() > 64) {
			reportError(rbi.location, "Integer representation exceeds Java long (" + rbi + ")");
		}
	}

	private void redefinedError(SleighSymbol sym, Tree t, String what) {
	    String msg = "symbol '" + sym.getName() + "' (from " + sym.getLocation() + ") redefined as " + what;
	    reportError(find(t), msg);
	}

	private void wildcardError(Tree t, String what) {
	    String msg = "wildcard (_) not allowed in " + what;
	    reportError(find(t), msg);
	}

	private void wrongSymbolTypeError(SleighSymbol sym, Location where, String type, String purpose) {
	    String msg = sym.getType() + " '" + sym + "' (defined at " + sym.getLocation() + ") is wrong type (should be " + type + ") in " + purpose;
	    reportError(where, msg);
	}

	private void undeclaredSymbolError(SleighSymbol sym, Location where, String purpose) {
	    String msg = "'" + sym + "' (used in " + purpose + ") is not declared in the pattern list";
	    reportError(where, msg);
	}

	private void unknownSymbolError(String text, Location loc, String type, String purpose) {
	    String msg = "unknown " + type + " '" + text + "' in " + purpose;
	    reportError(loc, msg);
	}

	private void invalidDynamicTargetError(Location loc, String purpose) {
	    String msg = "invalid dynamic target used in " + purpose;
	    reportError(loc, msg);
	}

	private Location find(Tree t) {
	    return env.getLocator().getLocation(t.getLine());
	}
	
	private SubtableSymbol findOrNewTable(Location loc, String name) {
		SleighSymbol sym = sc.findSymbol(name);
		if (sym == null) {
			SubtableSymbol ss = sc.newTable(loc, name);
			return ss;
		} else if(sym.getType() != symbol_type.subtable_symbol) {
			wrongSymbolTypeError(sym, loc, "subtable", "subconstructor");
			return null;
		} else {
			return (SubtableSymbol) sym;
		}
	}

	public String getErrorMessage(RecognitionException e, String[] tokenNames) {
	    return env.getParserErrorMessage(e, tokenNames);
	}

	public String getTokenErrorDisplay(Token t) {
	    return env.getTokenErrorDisplay(t);
	}

	public String getErrorHeader(RecognitionException e) {
	    return env.getErrorHeader(e);
	}

	void bail(String msg) {
	    throw new BailoutException(msg);
	}
}

root[ParsingEnvironment pe, SleighCompile sc] returns [int errors]
	@init {
		this.env = pe;
		this.sc = sc;
	}
	@after {
		$errors = env.getLexingErrors() + env.getParsingErrors();
	}
	:	endiandef
		(	definition
		|	constructorlike
		)*
	;

endiandef
	:	^(OP_ENDIAN s=endian) { sc.setEndian($s.value); }
	;

endian returns [int value]
	:	OP_BIG    { $value = 1; }
	|	OP_LITTLE { $value = 0; }
	;

definition
	:	(aligndef
	|	tokendef
	|	contextdef
	|	spacedef
	|	varnodedef
	|	bitrangedef
	|	pcodeopdef
	|	valueattach
	|	nameattach
	|	varattach
	)
	;

aligndef
	:	^(OP_ALIGNMENT i=integer) { sc.setAlignment($i.value.intValue()); }
	;

tokendef
	scope {
		TokenSymbol tokenSymbol;
	}
	@init {
		$tokendef::tokenSymbol = null;
	}
	:	^(OP_TOKEN n=specific_identifier["token definition"] i=integer {
			if (n != null) {
				SleighSymbol sym = sc.findSymbol($n.value.getText());
				if (sym != null) {
					redefinedError(sym, n, "token");
				} else {
					$tokendef::tokenSymbol = sc.defineToken(find(n), $n.value.getText(), $i.value.intValue(), 0);
				}
			}
		} fielddefs)
	|   ^(OP_TOKEN_ENDIAN n=specific_identifier["token definition"] i=integer s=endian {
			if (n != null) {
			    SleighSymbol sym = sc.findSymbol($n.value.getText());
			    if (sym != null) {
			        redefinedError(sym, n, "token");
			    } else {
			        $tokendef::tokenSymbol = sc.defineToken(find(n), $n.value.getText(), $i.value.intValue(), $s.value ==0 ? -1 : 1);
			    }
			}
	    } fielddefs)
	;

fielddefs
	:	^(OP_FIELDDEFS fielddef*)
	;

fielddef
	scope{
		FieldQuality fieldQuality;
	}
	@init {
		$fielddef::fieldQuality = null;
	}
	:	^(t=OP_FIELDDEF n=unbound_identifier["field"] s=integer e=integer {
			if (n != null) {
                long start = $s.value.longValue();
                long finish = $e.value.longValue();
                if (finish < start) {
                    reportError(find($t), "field '" + $n.value.getText() + "' starts at " + start + " and ends at " + finish);
                }
                $fielddef::fieldQuality = new FieldQuality($n.value.getText(), find($t), $s.value.longValue(), $e.value.longValue());
			}
		} fieldmods) {
			if ($fielddef.size() > 0 && $fielddef::fieldQuality != null) {
				if ($tokendef.size() > 0 && $tokendef::tokenSymbol != null) {
					if ($tokendef::tokenSymbol.getToken().getSize()*8 <= $fielddef::fieldQuality.high) {
						reportError(find($t), "field high must be less than token size");
					} else {
						sc.addTokenField(find(n), $tokendef::tokenSymbol, $fielddef::fieldQuality);
					}
				} else if ($contextdef.size() > 0 && $contextdef::varnode != null) {
					if (!sc.addContextField($contextdef::varnode, $fielddef::fieldQuality)) {
						reportError(find($t), "all context definitions must come before constructors");
					}
				}
			}
		}
	;

fieldmods
	:	^(OP_FIELD_MODS fieldmod+)
	|	OP_NO_FIELD_MOD
	;

fieldmod
    :   OP_SIGNED { if ($fielddef::fieldQuality != null) $fielddef::fieldQuality.signext = true; }
    |   OP_NOFLOW { if ($fielddef::fieldQuality != null) $fielddef::fieldQuality.flow = false; }
    |   OP_HEX { if ($fielddef::fieldQuality != null) $fielddef::fieldQuality.hex = true; }
    |   OP_DEC { if ($fielddef::fieldQuality != null) $fielddef::fieldQuality.hex = false; }
    ;

specific_identifier[String purpose] returns [Tree value]
	:	^(OP_IDENTIFIER s=.) { $value = $s; }
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$value = null;
		}
	;

unbound_identifier[String purpose] returns [Tree value]
	:	^(OP_IDENTIFIER s=.) {
	        // use PcodeCompile for symbol table while parsing pcode
        	SleighSymbol sym = pcode != null ? pcode.findSymbol($s.getText()) : sc.findSymbol($s.getText());
			if (sym != null) {
				redefinedError(sym, $s, purpose);
				$value = null;
			} else {
				$value = $s;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$value = null;
		}
	;

varnode_symbol[String purpose, boolean noWildcards] returns [VarnodeSymbol symbol]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "varnode", purpose);
			} else if(sym.getType() != symbol_type.varnode_symbol) {
				wrongSymbolTypeError(sym, find($s), "varnode", purpose);
			} else {
				$symbol = (VarnodeSymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			if (noWildcards) {
				wildcardError($t, purpose);
			}
			$symbol = null;
		}
	;

value_symbol[String purpose] returns [Pair<ValueSymbol,Location> symbol]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "value or context", purpose);
			} else if(sym.getType() == symbol_type.value_symbol
					|| sym.getType() == symbol_type.context_symbol) {
				$symbol = new Pair<ValueSymbol,Location>((ValueSymbol) sym, find($s));
			} else {
				wrongSymbolTypeError(sym, find($s), "value or context", purpose);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$symbol = null;
		}
	;

operand_symbol[String purpose] returns [OperandSymbol symbol]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = pcode.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "operand", purpose);
			} else if(sym.getType() != symbol_type.operand_symbol) {
				wrongSymbolTypeError(sym, find($s), "operand", purpose);
			} else {
				$symbol = (OperandSymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$symbol = null;
		}
	;

space_symbol[String purpose] returns [SpaceSymbol symbol]
	:	^(OP_IDENTIFIER s=.) {
			// use PcodeCompile for symbol table while parsing pcode
        	SleighSymbol sym = pcode != null ? pcode.findSymbol($s.getText()) : sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "space", purpose);
			} else if(sym.getType() != symbol_type.space_symbol) {
				wrongSymbolTypeError(sym, find($s), "space", purpose);
			} else {
				$symbol = (SpaceSymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$symbol = null;
		}
	;

specific_symbol[String purpose] returns [SpecificSymbol symbol]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = pcode.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "start, end, operand, epsilon, or varnode", purpose);
			} else if(sym.getType() != symbol_type.start_symbol
					&& sym.getType() != symbol_type.end_symbol
					&& sym.getType() != symbol_type.operand_symbol
					&& sym.getType() != symbol_type.epsilon_symbol
					&& sym.getType() != symbol_type.varnode_symbol) {
				undeclaredSymbolError(sym, find($s), purpose);
			} else {
				$symbol = (SpecificSymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$symbol = null;
		}
	;

family_symbol[String purpose] returns [FamilySymbol symbol]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "family", purpose);
			} else if(sym.getType() != symbol_type.value_symbol
					&& sym.getType() != symbol_type.valuemap_symbol
					&& sym.getType() != symbol_type.context_symbol
					&& sym.getType() != symbol_type.name_symbol
					&& sym.getType() != symbol_type.varnodelist_symbol) {
				wrongSymbolTypeError(sym, find($s), "family", purpose);
			} else {
				$symbol = (FamilySymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$symbol = null;
		}
	;

contextdef
	scope {
		VarnodeSymbol varnode;
	}
	@init {
		$contextdef::varnode = null;
	}
	:	^(OP_CONTEXT s=varnode_symbol["context definition", true] {
			if (s != null) {
				$contextdef::varnode = s;
			}
		} fielddefs)
	;

spacedef
	scope {
		SpaceQuality quality;
	}
	@init {
		$spacedef::quality = null;
	}
	:	^(OP_SPACE n=unbound_identifier["space"] {
			String name = "<parse error>";
			if (n != null) {
				name = n.getText();
			}
			$spacedef::quality = new SpaceQuality(name);
		} s=spacemods) {
			if (n != null) {
				sc.newSpace(find(n), $spacedef::quality);
			}
		}
	;

spacemods
	:	^(OP_SPACEMODS spacemod*)
	;

spacemod
	:	typemod
	|	sizemod
	|	wordsizemod
	|	OP_DEFAULT { $spacedef::quality.isdefault = true; }
	;

typemod
	:	^(OP_TYPE n=specific_identifier["space type qualifier"]) {
			if (n != null) {
				String typeName = n.getText();
				try {
					space_class type = space_class.valueOf(typeName);
					$spacedef::quality.type = type;
				} catch(IllegalArgumentException e) {
					reportError(find(n), "invalid space type '" + typeName + "'");
				}
			}
		}
	;

sizemod
	:	^(OP_SIZE i=integer) {
			$spacedef::quality.size = $i.value.intValue();
		}
	;

wordsizemod
	:	^(OP_WORDSIZE i=integer) {
			$spacedef::quality.wordsize = $i.value.intValue();
		}
	;

varnodedef
	:	^(OP_VARNODE s=space_symbol["varnode definition"] offset=integer size=integer l=identifierlist) {
			if (offset.bitLength() > 64) {
				throw new SleighError("Unsupported offset: " + String.format("0x\%x", offset),
					l.second.get(0));
			}
			if (size.bitLength() >= 32) {
				throw new SleighError("Unsupported size: " + String.format("0x\%x", size),
					l.second.get(0));
			}
			sc.defineVarnodes(s, $offset.value.longValue(), $size.value.intValue(), l.first, l.second);
		}
	;

identifierlist returns [Pair<VectorSTL<String>,VectorSTL<Location>> value]
	@init {
		VectorSTL<String> names = new VectorSTL<String>();
		VectorSTL<Location> locations = new VectorSTL<Location>();
	}
	@after {
		$value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
	}
	:	^(OP_IDENTIFIER_LIST (
			^(OP_IDENTIFIER s=.) { names.push_back($s.getText()); locations.push_back(find(s)); }
			| t=OP_WILDCARD { names.push_back($t.getText()); locations.push_back(find(t)); } )+)
	;

stringoridentlist returns [VectorSTL<String> value]
	@init {
		$value = new VectorSTL<String>();
	}
	:	^(OP_STRING_OR_IDENT_LIST (n=stringorident { $value.push_back(n); } )*)
	;

stringorident returns [String value]
	:	n=identifier { $value = $n.value; }
	|	s=qstring { $value = $s.value; }
	;

bitrangedef
	:	^(OP_BITRANGES sbitrange+)
	;

sbitrange
	:	^(OP_BITRANGE ^(OP_IDENTIFIER s=.) b=varnode_symbol["bitrange definition", true] i=integer j=integer) {
			sc.defineBitrange(find(s), $s.getText(), b, $i.value.intValue(), $j.value.intValue());
		}
	;

pcodeopdef
	:	^(OP_PCODEOP l=identifierlist) { sc.addUserOp(l.first, l.second); }
	;

valueattach
	@init {
		sc.calcContextLayout();
	}
	:	^(OP_VALUES a=valuelist["attach values"] b=intblist) { sc.attachValues(a.first, a.second, b); }
	;

intblist returns [VectorSTL<Long> value]
	@init {
		$value = new VectorSTL<Long>();
	}
	:	^(OP_INTBLIST (n=intbpart { $value.push_back(n.longValue()); } )*)
	;

intbpart returns [BigInteger value]
	:	t=OP_WILDCARD { $value = new RadixBigInteger(find(t), "BADBEEF", 16); }
	|	^(OP_NEGATE i=integer) { $value = i.negate(); }
	|	i=integer { $value = i; }
	;

nameattach
	@init {
		sc.calcContextLayout();
	}
	:	^(OP_NAMES a=valuelist["attach variables"] b=stringoridentlist) { sc.attachNames(a.first, a.second, b); }
	;

varattach
	@init {
		sc.calcContextLayout();
	}
	:	^(OP_VARIABLES a=valuelist["attach variables"] b=varlist["attach variables"]) {
			sc.attachVarnodes(a.first, a.second, b);
		}
	;

valuelist[String purpose] returns [Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>> value]
	@init {
		VectorSTL<SleighSymbol> symbols = new VectorSTL<SleighSymbol>();
		VectorSTL<Location> locations = new VectorSTL<Location>();
	}
	@after {
		$value = new Pair<VectorSTL<SleighSymbol>,VectorSTL<Location>>(symbols, locations);
	}
	:	^(OP_IDENTIFIER_LIST (n=value_symbol[purpose] {
			symbols.push_back(n.first);
			locations.push_back(n.second);
		} )+)
	;


varlist[String purpose] returns [VectorSTL<SleighSymbol> value]
	@init {
		$value = new VectorSTL<SleighSymbol>();
	}
	:	^(OP_IDENTIFIER_LIST (n=varnode_symbol[purpose, false] {
			$value.push_back(n);
		} )+)
	;

constructorlike
	:	macrodef
	|	{ sc.calcContextLayout(); } withblock
	|	{ sc.calcContextLayout(); } constructor
	;

macrodef
	scope {
		ConstructTpl macrobody;
	}
	@init {
		MacroSymbol symbol = null;
	}
	:	^(t=OP_MACRO n=unbound_identifier["macro"] a=arguments {
			symbol = sc.createMacro(find(n), n.getText(), a.first, a.second);
		} s=semantic[env, null, sc.pcode, $t, false, true]) {
			if (symbol != null) {
				sc.buildMacro(symbol, $macrodef::macrobody);
			}
		}
	;

arguments returns [Pair<VectorSTL<String>,VectorSTL<Location>> value]
	@init {
		VectorSTL<String> names = new VectorSTL<String>();
		VectorSTL<Location> locations = new VectorSTL<Location>();
	}
	@after {
		$value = new Pair<VectorSTL<String>,VectorSTL<Location>>(names, locations);
	}
	:	^(OP_ARGUMENTS (^(OP_IDENTIFIER s=.) { names.push_back(s.getText()); locations.push_back(find(s)); })+)
	|	OP_EMPTY_LIST
	;

withblock
	:	^(OP_WITH s=id_or_nil e=bitpat_or_nil b=contextblock {
			SubtableSymbol ss = null;
			if ($s.value != null) {
				ss = findOrNewTable(find($s.tree), $s.value);
				if (ss == null) bail("With block with invalid subtable identifier");
			}	
			sc.pushWith(ss, e, b);
		}
		constructorlikelist
		{
			sc.popWith();
		})
	;

id_or_nil returns [String value, Tree tree]
	:	v=identifier { $value = $v.value; $tree = $v.tree; }
	|	OP_NIL { $value = null; $tree = null; }
	;

bitpat_or_nil returns [PatternEquation value]
	:	v=bitpattern { $value = v; }
	|	OP_NIL { $value = null; }
	;

constructorlikelist
	: ^(OP_CTLIST ( definition | constructorlike )* )
	;

constructor
	:	^(OP_CONSTRUCTOR c=ctorstart e=bitpattern b=contextblock r=ctorsemantic[c]) {
			sc.buildConstructor(c, e, b, r);
		}
	;

ctorsemantic[Constructor ctor] returns [SectionVector value]
	:	^(t=OP_PCODE p=semantic[env, ctor.location, sc.pcode, $t, true, false]) {       $value = p; }
	|	^(OP_PCODE OP_UNIMPL) { /*unimpl unimplemented ; */ $value = null; }
	;

bitpattern returns [PatternEquation value]
	:	^(OP_BIT_PATTERN p=pequation) { $value = $p.value; }
	;

ctorstart returns [Constructor value]
	scope {
		boolean table;
		boolean firstTime;
	}
	@init {
		$ctorstart::table = false;
		$ctorstart::firstTime = true;
	}
	:	^(t=OP_SUBTABLE (^(OP_IDENTIFIER s=.) {
			SubtableSymbol ss = findOrNewTable(find($s), $s.getText());
			if (ss != null) {
				$value = sc.createConstructor(find($t), ss);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, "subconstructor");
		}) d=display[value]) {  }
	|	^(t=OP_TABLE {
			$value = sc.createConstructor(find(t), null);
			$ctorstart::table = "instruction".equals($value.getParent().getName());
		} d=display[value]) {  }
	;

display[Constructor ct]
	:	^(OP_DISPLAY p=pieces[ct])
	;

pieces[Constructor ct]
	:	printpiece[ct]*
	;

printpiece[Constructor ct]
	@after {
		$ctorstart::firstTime = false;
	}
	:	^(OP_IDENTIFIER t=.) {
			if ($ctorstart::table && $ctorstart::firstTime) {
				ct.addSyntax(t.getText());
			} else {
				sc.newOperand(find(t), ct, t.getText());
			}
		}
	|	w=whitespace {
			if (!$ctorstart::firstTime) {
				ct.addSyntax(" ");
			}
		}
	|	OP_CONCATENATE
	|	s=string { ct.addSyntax(s); }
	;

whitespace returns [String value]
	:	^(OP_WHITESPACE s=.) { $value = $s.getText(); }
	;

string returns [String value]
	:	^(OP_STRING s=.) { $value = $s.getText(); }
	|	^(OP_QSTRING s=.) { $value = $s.getText(); }
	;

pequation returns [PatternEquation value]
	@after {
		if (value == null) {
			throw new BailoutException("Pattern equation parsing returned null");
		}
	}
	:	^(t=OP_BOOL_OR l=pequation r=pequation) { $value = new EquationOr(find(t), l, r); }
	|	^(t=OP_SEQUENCE l=pequation r=pequation) { $value = new EquationCat(find(t), l, r); }
	|	^(t=OP_BOOL_AND l=pequation r=pequation) { $value = new EquationAnd(find(t), l, r); }

	|	^(t=OP_ELLIPSIS l=pequation) { $value = new EquationLeftEllipsis(find(t), l); }
	|	^(t=OP_ELLIPSIS_RIGHT l=pequation) { $value = new EquationRightEllipsis(find(t), l); }

	|	^(t=OP_EQUAL s=family_or_operand_symbol["pattern equation"] e=pexpression2) {
			SleighSymbol sym = sc.findSymbol(s.getText());
			if (sym instanceof OperandSymbol) {
				$value = sc.constrainOperand(find(t), (OperandSymbol) sym, e);
			} else {
				FamilySymbol fs = (FamilySymbol) sym;
				$value = new EqualEquation(find(t), fs.getPatternValue(), e);
			}
		}
	|	^(t=OP_NOTEQUAL f=family_symbol["pattern equation"] e=pexpression2) { $value = new NotEqualEquation(find(t), f.getPatternValue(), e); }
	|	^(t=OP_LESS f=family_symbol["pattern equation"] e=pexpression2) { $value = new LessEquation(find(t), f.getPatternValue(), e); }
	|	^(t=OP_LESSEQUAL f=family_symbol["pattern equation"] e=pexpression2) { $value = new LessEqualEquation(find(t), f.getPatternValue(), e); }
	|	^(t=OP_GREAT f=family_symbol["pattern equation"] e=pexpression2) { $value = new GreaterEquation(find(t), f.getPatternValue(), e); }
	|	^(t=OP_GREATEQUAL f=family_symbol["pattern equation"] e=pexpression2) { $value = new GreaterEqualEquation(find(t), f.getPatternValue(), e); }

	|	ps=pequation_symbol["pattern equation"] { $value = ps; }
	|	^(OP_PARENTHESIZED l=pequation) { $value = l; }
	;


family_or_operand_symbol[String purpose] returns [Tree value]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "family or operand", purpose);
			} else if(sym.getType() != symbol_type.value_symbol
					&& sym.getType() != symbol_type.valuemap_symbol
					&& sym.getType() != symbol_type.context_symbol
					&& sym.getType() != symbol_type.name_symbol
					&& sym.getType() != symbol_type.varnodelist_symbol
					&& sym.getType() != symbol_type.operand_symbol) {
				wrongSymbolTypeError(sym, find($s), "family or operand", purpose);
			} else {
				$value = $s;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
		}
	;

pequation_symbol[String purpose] returns [PatternEquation value]
	:	^(OP_IDENTIFIER s=.) {
			Location location = find(s);
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "family, operand, epsilon, or subtable", purpose);
			} else if(sym.getType() == symbol_type.value_symbol
					|| sym.getType() == symbol_type.valuemap_symbol
					|| sym.getType() == symbol_type.context_symbol
					|| sym.getType() == symbol_type.name_symbol
					|| sym.getType() == symbol_type.varnodelist_symbol) {
				$value = sc.defineInvisibleOperand(location, (FamilySymbol) sym);
			} else if(sym.getType() == symbol_type.operand_symbol) {
				OperandSymbol os = (OperandSymbol) sym;
				$value = new OperandEquation(location, os.getIndex()); sc.selfDefine(os);
			} else if(sym.getType() == symbol_type.epsilon_symbol) {
				SpecificSymbol ss = (SpecificSymbol) sym;
				$value = new UnconstrainedEquation(location, ss.getPatternExpression());
			} else if(sym.getType() == symbol_type.subtable_symbol) {
				SubtableSymbol ss = (SubtableSymbol) sym;
				$value = sc.defineInvisibleOperand(location, ss);
			} else {
				$value = null;
				wrongSymbolTypeError(sym, find($s), "family, operand, epsilon, or subtable", purpose);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
		}
	;

pexpression returns [PatternExpression value]
	:	^(t=OP_OR l=pexpression r=pexpression) { $value = new OrExpression(find(t), l, r); }
	|	^(t=OP_XOR l=pexpression r=pexpression) { $value = new XorExpression(find(t), l, r); }
	|	^(t=OP_AND l=pexpression r=pexpression) { $value = new AndExpression(find(t), l, r); }
	|	^(t=OP_LEFT l=pexpression r=pexpression) { $value = new LeftShiftExpression(find(t), l, r); }
	|	^(t=OP_RIGHT l=pexpression r=pexpression) { $value = new RightShiftExpression(find(t), l, r); }
	|	^(t=OP_ADD l=pexpression r=pexpression) { $value = new PlusExpression(find(t), l, r); }
	|	^(t=OP_SUB l=pexpression r=pexpression) { $value = new SubExpression(find(t), l, r); }
	|	^(t=OP_MULT l=pexpression r=pexpression) { $value = new MultExpression(find(t), l, r); }
	|	^(t=OP_DIV l=pexpression r=pexpression) { $value = new DivExpression(find(t), l, r); }

	|	^(t=OP_NEGATE l=pexpression) { $value = new MinusExpression(find(t), l); }
	|	^(t=OP_INVERT l=pexpression) { $value = new NotExpression(find(t), l); }

//	|	^(OP_APPLY n=identifier o=pexpression2_operands) { $value = $n.value + "(" + $o.value + ")"; } // for globalset!!!
	|	y=pattern_symbol["pattern expression"] { $value = $y.expr; }
	|	i=integer { $value = new ConstantValue(i.location, i.longValue()); }
	|	^(OP_PARENTHESIZED l=pexpression) { $value = l; }
	;

pexpression2 returns [PatternExpression value]
	:	^(t=OP_OR l=pexpression2 r=pexpression2) { $value = new OrExpression(find(t), l, r); }
	|	^(t=OP_XOR l=pexpression2 r=pexpression2) { $value = new XorExpression(find(t), l, r); }
	|	^(t=OP_AND l=pexpression2 r=pexpression2) { $value = new AndExpression(find(t), l, r); }
	|	^(t=OP_LEFT l=pexpression2 r=pexpression2) { $value = new LeftShiftExpression(find(t), l, r); }
	|	^(t=OP_RIGHT l=pexpression2 r=pexpression2) { $value = new RightShiftExpression(find(t), l, r); }
	|	^(t=OP_ADD l=pexpression2 r=pexpression2) { $value = new PlusExpression(find(t), l, r); }
	|	^(t=OP_SUB l=pexpression2 r=pexpression2) { $value = new SubExpression(find(t), l, r); }
	|	^(t=OP_MULT l=pexpression2 r=pexpression2) { $value = new MultExpression(find(t), l, r); }
	|	^(t=OP_DIV l=pexpression2 r=pexpression2) { $value = new DivExpression(find(t), l, r); }

	|	^(t=OP_NEGATE l=pexpression2) { $value = new MinusExpression(find(t), l); }
	|	^(t=OP_INVERT l=pexpression2) { $value = new NotExpression(find(t), l); }

//	|	^(OP_APPLY n=identifier o=pexpression2_operands) { $value = $n.value + "(" + $o.value + ")"; } // for globalset!!!
	|	y=pattern_symbol2["pattern expression"] { $value = $y.expr; }
	|	i=integer { $value = new ConstantValue(i.location, i.longValue()); }
	|	^(OP_PARENTHESIZED l=pexpression2) { $value = l; }
	;

pattern_symbol[String purpose] returns [PatternExpression expr]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "start, end, operand, epsilon, or varnode", purpose);
            } else if(sym.getType() == symbol_type.operand_symbol) {
                OperandSymbol os = (OperandSymbol) sym;
                if (os.getDefiningSymbol() != null && os.getDefiningSymbol().getType() == symbol_type.subtable_symbol) {
                    reportError(find($s), "Subtable symbol '" + sym.getName() + "' is not allowed in context block");
                }
                $expr = os.getPatternExpression();
			} else if(sym.getType() == symbol_type.start_symbol
					|| sym.getType() == symbol_type.end_symbol
					|| sym.getType() == symbol_type.epsilon_symbol
					|| sym.getType() == symbol_type.varnode_symbol) {
				SpecificSymbol ss = (SpecificSymbol) sym;
				$expr = ss.getPatternExpression();
			} else if(sym.getType() == symbol_type.value_symbol
					|| sym.getType() == symbol_type.valuemap_symbol
					|| sym.getType() == symbol_type.context_symbol
					|| sym.getType() == symbol_type.name_symbol
					|| sym.getType() == symbol_type.varnodelist_symbol) {
				if (sym.getType() == symbol_type.context_symbol) {
					FamilySymbol z = (FamilySymbol) sym;
					$expr = z.getPatternValue();
				} else {
					reportError(find($s), "Global symbol '" + sym.getName() + "' is not allowed in action expression");
				}
			} else {
				wrongSymbolTypeError(sym, find($s), "start, end, operand, epsilon, or varnode", purpose);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$expr = null;
		}
	;

pattern_symbol2[String purpose] returns [PatternExpression expr]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = sc.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "start, end, operand, epsilon, or varnode", purpose);
			} else if(sym.getType() == symbol_type.start_symbol
					|| sym.getType() == symbol_type.end_symbol
					|| sym.getType() == symbol_type.operand_symbol
					|| sym.getType() == symbol_type.epsilon_symbol
					|| sym.getType() == symbol_type.varnode_symbol) {
				SpecificSymbol ss = (SpecificSymbol) sym;
				$expr = ss.getPatternExpression();
			} else if(sym.getType() == symbol_type.value_symbol
					|| sym.getType() == symbol_type.valuemap_symbol
					|| sym.getType() == symbol_type.context_symbol
					|| sym.getType() == symbol_type.name_symbol
					|| sym.getType() == symbol_type.varnodelist_symbol) {
				FamilySymbol z = (FamilySymbol) sym;
				$expr = z.getPatternValue();
			} else {
				wrongSymbolTypeError(sym, find($s), "start, end, operand, epsilon, or varnode", purpose);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$expr = null;
		}
	;

contextblock returns [VectorSTL<ContextChange> value]
	:	^(OP_CONTEXT_BLOCK r=cstatements) { $value = r; }
	|	OP_NO_CONTEXT_BLOCK { $value = null; }
	;

cstatements returns[VectorSTL<ContextChange> r]
	@init {
		r = new VectorSTL<ContextChange>();
	}
	:	cstatement[r]+
	;

cstatement[VectorSTL<ContextChange> r]
	:	^(OP_ASSIGN ^(OP_IDENTIFIER id=.) e=pexpression) {
			SleighSymbol sym = sc.findSymbol($id.getText());
			if (sym == null) {
				unknownSymbolError($id.getText(), find($id), "context or operand", "context block lvalue");
			} else if(sym.getType() == symbol_type.context_symbol) {
				ContextSymbol t = (ContextSymbol) sym;
				if (!sc.contextMod(r, t, e)) {
					reportError(find($id), "Cannot use 'inst_next' to set context variable: '" + t.getName() + "'");
				}
			} else if(sym.getType() == symbol_type.operand_symbol) {
				OperandSymbol t = (OperandSymbol) sym;
				sc.defineOperand(find(id), t, e);
			} else {
				wrongSymbolTypeError(sym, find(id), "context or operand", "context block lvalue");
			}	
		}
	|	^(OP_APPLY ^(OP_IDENTIFIER id=.) ^(OP_IDENTIFIER arg1=.) ^(OP_IDENTIFIER arg2=.)) {
			if (!"globalset".equals(id.getText())) {
				reportError(find($id), "unknown context block function '" + id.getText() + "'");
			} else {
				SleighSymbol sym = sc.findSymbol($arg2.getText());
				if (sym == null) {
					unknownSymbolError($arg2.getText(), find($arg2), "context", "globalset call");
				} else if(sym.getType() == symbol_type.context_symbol) {
					ContextSymbol t = (ContextSymbol) sym;
					sym = sc.findSymbol($arg1.getText());
					if (sym == null) {
						unknownSymbolError($arg1.getText(), find($arg1), "family or specific", "globalset call");
					} else if(sym.getType() == symbol_type.value_symbol
							|| sym.getType() == symbol_type.valuemap_symbol
							|| sym.getType() == symbol_type.context_symbol
							|| sym.getType() == symbol_type.name_symbol
							|| sym.getType() == symbol_type.varnodelist_symbol
							|| sym.getType() == symbol_type.start_symbol
							|| sym.getType() == symbol_type.end_symbol
							|| sym.getType() == symbol_type.operand_symbol
							|| sym.getType() == symbol_type.epsilon_symbol
							|| sym.getType() == symbol_type.varnode_symbol) {
						sc.contextSet(r, (TripleSymbol) sym, t);
					} else {
						wrongSymbolTypeError(sym, find($arg1), "family or specific", "globalset call");
					}
				} else {
					wrongSymbolTypeError(sym, find(arg2), "context", "globalset call");
				}
			}
		}
	;

semantic[ParsingEnvironment pe, Location containerLoc, PcodeCompile pcode, Tree where, boolean sectionsAllowed, boolean isMacroParse] returns [SectionVector rtl]
	scope {
		SectionVector sections;
		boolean containsMultipleSections;
		boolean nextStatementMustBeSectionLabel;
		boolean canContainSections;
	}
	@init {
		ParsingEnvironment oldEnv = this.env;
		SleighCompile oldSC = sc;
		sc = null; // TODO: force failure with improper use of sc instead of pcode
		this.env = pe;
		this.pcode = pcode;
		
		$semantic::sections = null;
		$semantic::containsMultipleSections = false;
		$semantic::nextStatementMustBeSectionLabel = false;
		$semantic::canContainSections = sectionsAllowed;
	}
	@after {
		rtl = $semantic::sections;
	}
	:	^(x=OP_SEMANTIC c=code_block[find($x)] {
			if (c != null) {
				if (c.getOpvec().empty() && c.getResult() == null) {
				    Location loc = find(where);
				    if (loc == null) {
				       loc = containerLoc;
				    }
					pcode.recordNop(loc);
				}
				if ($semantic::containsMultipleSections) {
					$semantic::sections = pcode.finalNamedSection($semantic::sections, c);
				} else {
					if (!isMacroParse) {
						$semantic::sections = pcode.standaloneSection(c);
					} else {
						$macrodef::macrobody = c;
					}
				}
			}
		}
		)
	;
	finally {
	   this.sc = oldSC;
	   this.env = oldEnv;
	   this.pcode = null;
	}

code_block[Location startingPoint] returns [ConstructTpl rtl]
	scope {
		Location stmtLocation;
	}
	scope Block;
	@init {
		$Block::ct = new ConstructTpl(startingPoint);
		$code_block::stmtLocation = new Location("<internal error populating statement location>", 0);
	}
	@after {
		$rtl = $Block::ct;
	}
	:	statements
	|	OP_NOP
	;

statements
	:	statement*
	;

statement
	scope Return;
	@init {
		VectorSTL<OpTpl> ops = new VectorSTL<OpTpl>();
		$Return::noReturn = false;
		boolean wasSectionLabel = false;
		boolean lookingForSectionLabel = $semantic::nextStatementMustBeSectionLabel;
	}
	@after {
		if (lookingForSectionLabel && !wasSectionLabel) {
			reportError($code_block::stmtLocation, "No statements allowed after export");
		}
		$semantic::nextStatementMustBeSectionLabel = false;
		if (ops != null && !$Block::ct.addOpList(ops)) {
			reportError($code_block::stmtLocation, "Multiple delayslot declarations");
		}
	}
	:	r=assignment      { ops = r; }
	|	declaration		  { ops = null; }
	|	r=funcall         { ops = r; }
	|	r=build_stmt      { ops = r; }
	|	r=crossbuild_stmt { ops = r; }
	|	r=goto_stmt       { ops = r; }
	|	r=cond_stmt       { ops = r; }
	|	r=call_stmt       { ops = r; }
	|	r=return_stmt     { ops = r; }
	|	l=label {
			if (l != null) {
				ops = pcode.placeLabel(l.first, l.second);
			}
		}
	|	e=export[$Block::ct] {
			if ($semantic::containsMultipleSections) {
				reportError($code_block::stmtLocation, "Export only allowed in default section");
			}
			$Block::ct = e;
			$semantic::nextStatementMustBeSectionLabel = true;
		}
	|	s=section_label {
			if(!$semantic::canContainSections) {
				reportError($code_block::stmtLocation, "No sections allowed");
			}
			wasSectionLabel = true;
			if ($semantic::containsMultipleSections) {
				$semantic::sections = pcode.nextNamedSection($semantic::sections, $Block::ct, s.second);
			} else {
				$semantic::sections = pcode.firstNamedSection($Block::ct, s.second);
			}
			if ($Block::ct.getOpvec().empty() && $Block::ct.getResult() == null) {
					pcode.recordNop(s.first);
			}
			$semantic::containsMultipleSections = true;
			$Block::ct = new ConstructTpl(s.first);
		}
	;

declaration
	:	^(OP_LOCAL n=unbound_identifier["sized local declaration"] i=integer) {
			pcode.newLocalDefinition(find(n), n.getText(), $i.value.intValue());
		}
	|	^(OP_LOCAL n=unbound_identifier["local declaration"]) {
			pcode.newLocalDefinition(find(n), n.getText());
		}
	;

label returns [Pair<Location,LabelSymbol> result]
	:	^(OP_LABEL	(^(OP_IDENTIFIER s=.) {
					SleighSymbol sym = pcode.findSymbol($s.getText());
					if (sym != null) {
						if(sym.getType() != symbol_type.label_symbol) {
							wrongSymbolTypeError(sym, find($s), "label", "label");
						} else {
							$result = new Pair<Location,LabelSymbol>(find(s), (LabelSymbol) sym);
						}
					} else {
						Location where = find(s);
						$result = new Pair<Location,LabelSymbol>(where, pcode.defineLabel(where, $s.getText()));
					}
				}
			|	t=OP_WILDCARD {
					wildcardError($t, "label");
				}))
	;

section_label returns [Pair<Location,SectionSymbol> result]
	:	^(OP_SECTION_LABEL	(^(OP_IDENTIFIER s=.) {
					SleighSymbol sym = pcode.findSymbol($s.getText());
					if (sym != null) {
						if(sym.getType() != symbol_type.section_symbol) {
							wrongSymbolTypeError(sym, find($s), "section", "section");
						} else {
							$result = new Pair<Location,SectionSymbol>(find(s), (SectionSymbol) sym);
						}
					} else {
						Location where = find(s);
						$result = new Pair<Location,SectionSymbol>(where, pcode.newSectionSymbol(where, $s.getText()));
					}
				}
			|	t=OP_WILDCARD {
					wildcardError($t, "section");
				}))
	;

section_symbol[String purpose] returns [SectionSymbol value]
	:	^(OP_IDENTIFIER s=.) {
			Location location = find(s);
			SleighSymbol sym = pcode.findSymbol($s.getText());
			if (sym == null) {
				$value = pcode.newSectionSymbol(location, $s.getText());
			} else if(sym.getType() != symbol_type.section_symbol) {
				wrongSymbolTypeError(sym, find($s), "section", purpose);
			} else {
				$value = (SectionSymbol) sym;
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
		}
	;

assignment returns [VectorSTL<OpTpl> value]
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_ASSIGN ^(OP_BITRANGE ss=specific_symbol["bit range assignment"] a=integer b=integer) e=expr) {
			$value = pcode.assignBitRange(find(t), ss.getVarnode(), $a.value.intValue(), $b.value.intValue(), e);	
		}
	|	^(t=OP_ASSIGN ^(OP_DECLARATIVE_SIZE n=unbound_identifier["variable declaration/assignment"] i=integer) e=expr) {
			$value = pcode.newOutput(find(n), true, e, n.getText(), $i.value.intValue());
		}
	|	^(OP_LOCAL t=OP_ASSIGN ^(OP_DECLARATIVE_SIZE n=unbound_identifier["variable declaration/assignment"] i=integer) e=expr) {
			$value = pcode.newOutput(find(n), true, e, n.getText(), $i.value.intValue());
		}
	|	^(OP_LOCAL t=OP_ASSIGN n=unbound_identifier["variable declaration/assignment"] e=expr) {
			$value = pcode.newOutput(find(n), true, e, n.getText());
		}
	|	^(t=OP_ASSIGN ^(OP_IDENTIFIER id=.) e=expr) {
			SleighSymbol sym = pcode.findSymbol($id.getText());
			if (sym == null) {
				$value = pcode.newOutput(find(id), false, e, $id.getText());	
			} else if(sym.getType() != symbol_type.start_symbol
					&& sym.getType() != symbol_type.end_symbol
					&& sym.getType() != symbol_type.operand_symbol
					&& sym.getType() != symbol_type.epsilon_symbol
					&& sym.getType() != symbol_type.varnode_symbol) {
				wrongSymbolTypeError(sym, find(id), "start, end, operand, epsilon, or varnode", "assignment");
			} else {
				VarnodeTpl v = ((SpecificSymbol) sym).getVarnode();
				e.setOutput(find(t), v);
				$value = ExprTree.toVector(e);
			}	
		}
	|	^(OP_ASSIGN t=OP_WILDCARD e=expr) {
			wildcardError($t, "assignment");
		}
	|	^(t=OP_ASSIGN s=sizedstar f=expr) {
			$value = pcode.createStore(find(t), s.first, s.second, f);
		}
	;

bitrange returns [ExprTree value]
	:	^(t=OP_BITRANGE ss=specific_symbol["bit range"] a=integer b=integer) { $value = pcode.createBitRange(find(t), ss, $a.value.intValue(), $b.value.intValue()); }
	;

sizedstar returns [Pair<StarQuality, ExprTree> value]
	@init {
		StarQuality q = null;
	}
	@after {
		$value = new Pair<StarQuality, ExprTree>(q, e);
	}
	:	^(t=OP_DEREFERENCE s=space_symbol["sized star operator"] i=integer e=expr) {
			q = new StarQuality(find(t));
			q.setSize($i.value.intValue());
			q.setId(new ConstTpl(s.getSpace()));
		}
	|	^(t=OP_DEREFERENCE s=space_symbol["sized star operator"] e=expr) {
			q = new StarQuality(find(t));
			q.setSize(0);
			q.setId(new ConstTpl(s.getSpace()));
		}
	|	^(t=OP_DEREFERENCE i=integer e=expr) {
			q = new StarQuality(find(t));
			q.setSize($i.value.intValue());
			q.setId(new ConstTpl(pcode.getDefaultSpace()));
		}
	|	^(t=OP_DEREFERENCE e=expr) {
			q = new StarQuality(find(t));
			q.setSize(0);
			q.setId(new ConstTpl(pcode.getDefaultSpace()));
		}
	;

sizedstarv returns [Pair<StarQuality, VarnodeTpl> value]
	@init {
		StarQuality q = null;
	}
	@after {
		$value = new Pair<StarQuality, VarnodeTpl>(q, ss.getVarnode());
	}
	:	^(t=OP_DEREFERENCE s=space_symbol["sized star operator"] i=integer ss=specific_symbol["varnode reference"]) {
			q = new StarQuality(find(t));
			q.setSize($i.value.intValue());
			q.setId(new ConstTpl(s.getSpace()));
		}
	|	^(t=OP_DEREFERENCE s=space_symbol["sized star operator"] ss=specific_symbol["varnode reference"]) {
			q = new StarQuality(find(t));
			q.setSize(0);
			q.setId(new ConstTpl(s.getSpace()));
		}
	|	^(t=OP_DEREFERENCE i=integer ss=specific_symbol["varnode reference"]) {
			q = new StarQuality(find(t));
			q.setSize($i.value.intValue());
			q.setId(new ConstTpl(pcode.getDefaultSpace()));
		}
	|	^(t=OP_DEREFERENCE ss=specific_symbol["varnode reference"]) {
			q = new StarQuality(find(t));
			q.setSize(0);
			q.setId(new ConstTpl(pcode.getDefaultSpace()));
		}
	;

funcall returns [VectorSTL<OpTpl> value]
	@init {
		$Return::noReturn = true;
	}
	:	e=expr_apply {
			if (e instanceof VectorSTL<?>)
				$value = (VectorSTL<OpTpl>) e;
			else {
				Location loc = null;
				if (e instanceof ExprTree) {
					loc = ((ExprTree)e).location;
				}
				reportError(loc,"Functional operator requires a return value");
			}
		}
	;

build_stmt returns [VectorSTL<OpTpl> ops]
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_BUILD s=operand_symbol["build statement"]) {
			$ops = pcode.createOpConst(find(t), OpCode.CPUI_MULTIEQUAL, s.getIndex());
		}
	;

crossbuild_stmt returns [VectorSTL<OpTpl> ops]
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_CROSSBUILD v=varnode s=section_symbol["crossbuild statement"]) {
			$ops = pcode.createCrossBuild(find(t), v, s);
		}
	;

goto_stmt returns [VectorSTL<OpTpl> ops]
	scope Jump;
	@init {
		$Jump::indirect = false;
	}
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_GOTO j=jumpdest["goto destination"]) {
			$ops = pcode.createOpNoOut(find(t), $Jump::indirect ? OpCode.CPUI_BRANCHIND : OpCode.CPUI_BRANCH, j);
		}
	;

jump_symbol[String purpose] returns [VarnodeTpl value]
	:	^(OP_IDENTIFIER s=.) {
			SleighSymbol sym = pcode.findSymbol($s.getText());
			if (sym == null) {
				unknownSymbolError($s.getText(), find($s), "start, end, or operand", purpose);
			} else if(sym.getType() == symbol_type.start_symbol || sym.getType() == symbol_type.end_symbol) {
				SpecificSymbol ss = (SpecificSymbol) sym;
				$value = new VarnodeTpl(find($s), new ConstTpl(ConstTpl.const_type.j_curspace),
					ss.getVarnode().getOffset(),
					new ConstTpl(ConstTpl.const_type.j_curspace_size));
			} else if(sym.getType() == symbol_type.operand_symbol) {
				OperandSymbol os = (OperandSymbol) sym;
				$value = os.getVarnode();
				os.setCodeAddress();
			} else {
				wrongSymbolTypeError(sym, find($s), "start, end, or operand", purpose);
			}
		}
	|	t=OP_WILDCARD {
			wildcardError($t, purpose);
			$value = null;
		}
	;

jumpdest[String purpose] returns [ExprTree value]
	:	^(t=OP_JUMPDEST_SYMBOL ss=jump_symbol[purpose]) {
			$value = new ExprTree(find(t), ss);
		}
	|	^(t=OP_JUMPDEST_DYNAMIC e=expr) {
			$value = e;
			if(Jump_stack.isEmpty()) {
				invalidDynamicTargetError(find(t), purpose);
			} else {
				$Jump::indirect = true;
			}
		}
	|	^(t=OP_JUMPDEST_ABSOLUTE i=integer) {
			value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(ConstTpl.const_type.j_curspace),
				new ConstTpl(ConstTpl.const_type.real, $i.value.intValue()),
				new ConstTpl(ConstTpl.const_type.j_curspace_size)));
		}
	|	^(t=OP_JUMPDEST_RELATIVE i=integer s=space_symbol[purpose]) {
			AddrSpace spc = s.getSpace();
			value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(spc),
				new ConstTpl(ConstTpl.const_type.real, $i.value.intValue()),
				new ConstTpl(ConstTpl.const_type.real, spc.getAddrSize())));
		}
	|	^(t=OP_JUMPDEST_LABEL l=label) {
			value = new ExprTree(find(t), new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
				new ConstTpl(ConstTpl.const_type.j_relative, l.second.getIndex()),
				new ConstTpl(ConstTpl.const_type.real, 4)));
			l.second.incrementRefCount();
		}
	;

cond_stmt returns [VectorSTL<OpTpl> ops]
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_IF e=expr ^(OP_GOTO j=jumpdest["goto destination"])) {
			$ops = pcode.createOpNoOut(find(t), OpCode.CPUI_CBRANCH, j, e);
		}
	;

call_stmt returns [VectorSTL<OpTpl> ops]
	scope Jump;
	@init {
		$Jump::indirect = false;
	}
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_CALL j=jumpdest["call destination"]) {
			$ops = pcode.createOpNoOut(find(t), $Jump::indirect ? OpCode.CPUI_CALLIND : OpCode.CPUI_CALL, j);
		}
	;

return_stmt returns [VectorSTL<OpTpl> ops]
	@after {
		$code_block::stmtLocation = find(t);
	}
	:	^(t=OP_RETURN e=expr) {
			$ops = pcode.createOpNoOut(find(t), OpCode.CPUI_RETURN, e);
		}
	;

export[ConstructTpl rtl] returns [ConstructTpl value]
	:	^(t=OP_EXPORT q=sizedstarv) {
			$value = pcode.setResultStarVarnode(rtl, q.first, q.second);
			$code_block::stmtLocation = find(t);
		}
	|	^(t=OP_EXPORT v=varnode) {
			$value = pcode.setResultVarnode(rtl, v);
			$code_block::stmtLocation = find(t);
		}
	;

expr returns [ExprTree value]
	:	^(t=OP_BOOL_OR l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_BOOL_OR,l,r); }
	|	^(t=OP_BOOL_XOR l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_BOOL_XOR,l,r); }
	|	^(t=OP_BOOL_AND l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_BOOL_AND,l,r); }

	|	^(t=OP_OR l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_OR,l,r); }
	|	^(t=OP_XOR l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_XOR,l,r); }
	|	^(t=OP_AND l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_AND,l,r); }

	|	^(t=OP_EQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_EQUAL,l,r); }
	|	^(t=OP_NOTEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_NOTEQUAL,l,r); }
	|	^(t=OP_FEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_EQUAL,l,r); }
	|	^(t=OP_FNOTEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NOTEQUAL,l,r); }

	|	^(t=OP_LESS l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,l,r); }
	|	^(t=OP_GREATEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,r,l); }
	|	^(t=OP_LESSEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_LESSEQUAL,l,r); }
	|	^(t=OP_GREAT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_LESS,r,l); }
	|	^(t=OP_SLESS l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,l,r); }
	|	^(t=OP_SGREATEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,r,l); }
	|	^(t=OP_SLESSEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESSEQUAL,l,r); }
	|	^(t=OP_SGREAT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SLESS,r,l); }
	|	^(t=OP_FLESS l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,l,r); }
	|	^(t=OP_FGREATEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,r,l); }
	|	^(t=OP_FLESSEQUAL l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESSEQUAL,l,r); }
	|	^(t=OP_FGREAT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_LESS,r,l); }

	|	^(t=OP_LEFT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_LEFT,l,r); }
	|	^(t=OP_RIGHT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_RIGHT,l,r); }
	|	^(t=OP_SRIGHT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SRIGHT,l,r); }

	|	^(t=OP_ADD l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_ADD,l,r); }
	|	^(t=OP_SUB l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SUB,l,r); }
	|	^(t=OP_FADD l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_ADD,l,r); }
	|	^(t=OP_FSUB l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_SUB,l,r); }

	|	^(t=OP_MULT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_MULT,l,r); }
	|	^(t=OP_DIV l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_DIV,l,r); }
	|	^(t=OP_REM l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_REM,l,r); }
	|	^(t=OP_SDIV l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SDIV,l,r); }
	|	^(t=OP_SREM l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_SREM,l,r); }
	|	^(t=OP_FMULT l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_MULT,l,r); }
	|	^(t=OP_FDIV l=expr r=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_DIV,l,r); }

	|	^(t=OP_NOT l=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_BOOL_NEGATE,l); }
	|	^(t=OP_INVERT l=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_NEGATE,l); }
	|	^(t=OP_NEGATE l=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_INT_2COMP,l); }
	|	^(t=OP_FNEGATE l=expr) { $value = pcode.createOp(find(t), OpCode.CPUI_FLOAT_NEG,l); }
	|	s=sizedstar { $value = pcode.createLoad(s.first.location, s.first, s.second); }

	|	a=expr_apply { $value = (ExprTree) $a.value; }
	|	v=varnode { $value = new ExprTree(v.location, v); }
	|	b=bitrange { $value = $b.value; }
	|	i=integer { $value = new ExprTree(i.location, new VarnodeTpl(i.location, new ConstTpl(pcode.getConstantSpace()),
				new ConstTpl(ConstTpl.const_type.real, $i.value.longValue()),
				new ConstTpl(ConstTpl.const_type.real, 0)));
		}
	|	^(OP_PARENTHESIZED l=expr) { $value = l; }

	|	^(t=OP_BITRANGE2 ss=specific_symbol["expression"] i=integer) {
			$value = pcode.createBitRange(find(t), ss, 0, ($i.value.intValue() * 8));
		}
	;

expr_apply returns [Object value]
	@after {
		$code_block::stmtLocation = find(x);
	}
	:	^(x=OP_APPLY ^(t=OP_IDENTIFIER s=.) o=expr_operands) {
			Object internalFunction = pcode.findInternalFunction(find($s), $s.getText(), o);
			if (internalFunction == null) {
				SleighSymbol sym = pcode.findSymbol($s.getText());
				if (sym == null) {
					unknownSymbolError($s.getText(), find($s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
				} else if(sym.getType() == symbol_type.userop_symbol) {
					if($Return::noReturn) {
						$value = pcode.createUserOpNoOut(find(s), (UserOpSymbol) sym, o);
					} else {
						$value = pcode.createUserOp((UserOpSymbol) sym, o);
					}
				} else if(sym.getType() == symbol_type.macro_symbol) {
					if($Return::noReturn) {
						$value = pcode.createMacroUse(find(x), (MacroSymbol) sym, o);
					} else {
						pcode.reportError(find($t), "macro invocation not allowed as expression");
					}
				} else if(sym.getType() == symbol_type.start_symbol
					|| sym.getType() == symbol_type.end_symbol
					|| sym.getType() == symbol_type.operand_symbol
					|| sym.getType() == symbol_type.epsilon_symbol
					|| sym.getType() == symbol_type.varnode_symbol) {
					if (o.size() != 1) {
						pcode.reportError(find($t), "subpiece operation requires a single operand");
					} else {
						$value = pcode.createOp(find($s), OpCode.CPUI_SUBPIECE,new ExprTree(find($s), ((SpecificSymbol)sym).getVarnode()), o.get(0));
					}
				} else {
					wrongSymbolTypeError(sym, find($s), "macro, userop, or specific symbol", "macro, user operation, or subpiece application");
				}
			} else {
				$value = internalFunction;
			}
		}
	|	^(x=OP_APPLY t=OP_WILDCARD o=expr_operands) {
			wildcardError($t, "function application");
		}
	;

expr_operands returns [VectorSTL<ExprTree> value]
	scope Return;
	@init {
		$value = new VectorSTL<ExprTree>();
		$Return::noReturn = false;
	}
	:	(e=expr { value.push_back(e); })*
	;

varnode returns [VarnodeTpl value]
	:	ss=specific_symbol["varnode reference"] { $value = ss.getVarnode(); }
	|	^(t=OP_TRUNCATION_SIZE n=integer m=integer) {
			if ($m.value.longValue() > 8) {
				reportError(find(t), "Constant varnode size must not exceed 8 (" +
				$n.value.longValue() + ":" + $m.value.longValue() + ")");
			}
			$value = new VarnodeTpl(find(t), new ConstTpl(pcode.getConstantSpace()),
				new ConstTpl(ConstTpl.const_type.real, $n.value.longValue()),
				new ConstTpl(ConstTpl.const_type.real, $m.value.longValue()));
		}
	|	^(OP_ADDRESS_OF ^(OP_SIZING_SIZE i=integer) v=varnode) { $value = pcode.addressOf(v, $i.value.intValue()); }
	|	^(OP_ADDRESS_OF v=varnode) { $value = pcode.addressOf(v, 0); }
	;

qstring returns [String value]
	:	^(OP_QSTRING s=.) { $value = $s.getText(); }
	;

identifier returns [String value, Tree tree]
	:	^(OP_IDENTIFIER s=.) { $value = $s.getText(); $tree = s; }
	|	t=OP_WILDCARD { $value = null; $tree = s; }
	;

integer returns [RadixBigInteger value]
	:	^(OP_HEX_CONSTANT s=.) { $value = new RadixBigInteger(find(s), $s.getText().substring(2), 16); check($value); }
	|	^(OP_DEC_CONSTANT s=.) { $value = new RadixBigInteger(find(s), $s.getText()); check($value); }
	|	^(OP_BIN_CONSTANT s=.) { $value = new RadixBigInteger(find(s), $s.getText().substring(2), 2); check($value); }
	;
