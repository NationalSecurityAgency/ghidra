tree grammar SleighEcho;

options {
	ASTLabelType=CommonTree;
	tokenVocab=SleighLexer;
}

@header {
	import java.io.PrintStream;

	import org.antlr.runtime.*;
	import org.antlr.runtime.tree.*;
}

@members {
	public PrintStream out = System.out;

	void ot(String s) {
	    out.print(s);
	}

	void out(String s) {
	    out.println(s);
	}
}

root
	:	endiandef
		(	definition
		|	constructorlike
		)*
	;

endiandef
	:	^(OP_ENDIAN s=endian) { out("define endian=" + $s.text + ";"); }
	;

endian
	:	OP_BIG
	|	OP_LITTLE
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
	:	^(OP_ALIGNMENT i=integer) { out("define alignment=" + $i.value + ";"); }
	;

tokendef
	:	^(OP_TOKEN n=identifier i=integer { out("define token " + $n.value + "(" + $i.value + ")"); } fielddefs)
	|   ^(OP_TOKEN_ENDIAN n=identifier i=integer s=endian { out("define token endian" + $n.value + "(" + $i.value + ")"); } fielddefs)
	;

fielddefs
	:	^(OP_FIELDDEFS fielddef*) { out(";"); }
	;

fielddef
	:	^(OP_FIELDDEF n=identifier s=integer e=integer f=fieldmods) { out("  " + $n.value + " = (" + $s.value + "," + $e.value + ")" + $f.value); }
	;


fieldmods returns [String value]
    :   ^(OP_FIELD_MODS { $value = ""; } (n=fieldmod { $value += " " + $n.value; } )+ )
    |   OP_NO_FIELD_MOD { $value = ""; }
    ;

fieldmod returns [String value]
    :   OP_SIGNED { $value = "signed"; }
    |   OP_NOFLOW { $value = "noflow"; }
    |   OP_HEX { $value = "hex"; }
    |   OP_DEC { $value = "dec"; }
    ;

contextdef
	:	^(OP_CONTEXT n=identifier { out("define context " + $n.value); } fielddefs)
	;

spacedef
	:	^(OP_SPACE n=identifier s=spacemods) { out("define space " + $n.value + $s.value + ";"); }
	;

spacemods returns [String value]
@init { $value = ""; }
	:	^(OP_SPACEMODS (s=spacemod { $value += " " + $s.value; })*)
	;

spacemod returns [String value]
	:	t=typemod { $value = $t.value; }
	|	s=sizemod { $value = $s.value; }
	|	w=wordsizemod { $value = $w.value; }
	|	OP_DEFAULT { $value = "default"; }
	;

typemod returns [String value]
	:	^(OP_TYPE n=type) { $value = "type=" + $n.value; }
	;

type returns [String value]
	:	n=identifier { $value = $n.value; }
	;

sizemod returns [String value]
	:	^(OP_SIZE i=integer) { $value = "size=" + $i.value; }
	;

wordsizemod returns [String value]
	:	^(OP_WORDSIZE i=integer) { $value = "wordsize=" + $i.value; }
	;

varnodedef
	:	^(OP_VARNODE n=identifier offset=integer size=integer l=identifierlist) { out("define " + $n.value + " offset=" + $offset.value + " size=" + $size.value + " " + $l.value + ";"); }
	;

identifierlist returns [String value]
	:	^(OP_IDENTIFIER_LIST { $value = "["; } (n=identifier { $value += " " + $n.value; } )+) { $value += " ]"; }
	;

stringoridentlist returns [String value]
	:	^(OP_STRING_OR_IDENT_LIST { $value = "["; } (n=stringorident { $value += " " + $n.value; } )+) { $value += " ]"; }
	;

stringorident returns [String value]
	:	n=identifier { $value = $n.value; }
	|	s=qstring { $value = $s.value; }
	;

bitrangedef
	:	^(OP_BITRANGES { ot("define bitrange "); } bitranges)
	;

bitranges
@init { String sp = ""; }
	:	(s=sbitrange { out(sp + s); sp = "  "; })+
	;

sbitrange returns [String value]
	:	 ^(OP_BITRANGE a=identifier b=identifier i=integer j=integer) { $value = $a.value + " = " + $b.value + " [" + $i.value + "," + $j.value + "]"; }
	;

pcodeopdef
	:	^(OP_PCODEOP l=identifierlist) { out("define pcodeop " + $l.value + ";"); }
	;

valueattach
	:	^(OP_VALUES a=identifierlist b=intblist) { out("attach values " + $a.value + " " + $b.value + ";"); }
	;

intblist returns [String value]
	:	^(OP_INTBLIST { $value = "["; } (n=intbpart { $value += " " + $n.value; } )+) { $value += " ]"; }
	;

intbpart returns [String value]
	:	OP_WILDCARD { $value = "_"; }
	|	^(OP_NEGATE i=integer) { $value = "-" + $i.value; }
	|	i=integer { $value = $i.value; }
	;

nameattach
	:	^(OP_NAMES a=identifierlist b=stringoridentlist) { out("attach names " + $a.value + " " + $b.value + ";"); }
	;

varattach
	:	^(OP_VARIABLES a=identifierlist b=identifierlist) { out("attach variables " + $a.value + " " + $b.value + ";"); }
	;

constructorlike
	:	macrodef
	|	constructor
	;

macrodef
	:	^(OP_MACRO n=identifier a=arguments { out("macro " + $n.value + "(" + $a.value + ")" ); } semantic)
	;

arguments returns [String value]
	:	^(OP_ARGUMENTS l=oplist) { $value = $l.value; }
	|	OP_EMPTY_LIST { $value = ""; }
	;

oplist returns [String value]
@init { String comma = ""; $value = ""; }
	:	(n=identifier { $value += comma + $n.value; comma = ","; })+
	;

constructor
	:	^(OP_CONSTRUCTOR c=ctorstart b=bitpattern { ot($c.value + "is " + $b.value + " "); } contextblock ctorsemantic)
	;

ctorsemantic
	:	^(OP_PCODE semantic)
	|	^(OP_PCODE OP_UNIMPL) { out(" unimpl"); }
	;

bitpattern returns [String value]
	:	^(OP_BIT_PATTERN p=pequation) { $value = $p.value; }
	;

ctorstart returns [String value]
	:	^(OP_SUBTABLE i=identifier d=display) { $value = $i.value + ":" + $d.value; }
	|	^(OP_TABLE d=display) { $value = ":" + $d.value; }
	;

display returns [String value]
	:	^(OP_DISPLAY p=pieces) { $value = $p.value; }
	;

pieces returns [String value]
@init { $value = ""; }
	:	(p=printpiece { $value += $p.value; })*
	;

printpiece returns [String value]
	:	i=identifier { $value = $i.value; }
	|	w=whitespace { $value = $w.value; }
	|	OP_CONCATENATE { $value = "^"; }
	|	s=string { $value = $s.value; }
	;

whitespace returns [String value]
	:	^(OP_WHITESPACE s=.) { $value = $s.getText(); }
	;

string returns [String value]
	:	^(OP_STRING s=.) { $value = $s.getText(); }
	|	^(OP_QSTRING s=.) { $value = "\"" + $s.getText() + "\""; }
	;

pequation returns [String value]
	:	^(OP_BOOL_OR l=pequation r=pequation) { $value = $l.value + " | " + $r.value; }
	|	^(OP_SEQUENCE l=pequation r=pequation) { $value = $l.value + " ; " + $r.value; }
	|	^(OP_BOOL_AND l=pequation r=pequation) { $value = $l.value + " & " + $r.value; }

	|	^(OP_ELLIPSIS l=pequation) { $value = "... " + $l.value; }
	|	^(OP_ELLIPSIS_RIGHT l=pequation) { $value = $l.value + " ..."; }

	|	^(OP_EQUAL n=identifier x=pexpression2) { $value = $n.value + " = " + $x.value; }
	|	^(OP_NOTEQUAL n=identifier x=pexpression2) { $value = $n.value + " != " + $x.value; }
	|	^(OP_LESS n=identifier x=pexpression2) { $value = $n.value + " < " + $x.value; }
	|	^(OP_LESSEQUAL n=identifier x=pexpression2) { $value = $n.value + " <= " + $x.value; }
	|	^(OP_GREAT n=identifier x=pexpression2) { $value = $n.value + " > " + $x.value; }
	|	^(OP_GREATEQUAL n=identifier x=pexpression2) { $value = $n.value + " >= " + $x.value; }

	|	n=identifier { $value = $n.value; }
	|	^(OP_PARENTHESIZED l=pequation) { $value = "(" + $l.value + ")"; }
	;


pexpression2 returns [String value]
	:	^(OP_OR l=pexpression2 r=pexpression2) { $value = $l.value + " \$or " + $r.value; }
	|	^(OP_XOR l=pexpression2 r=pexpression2) { $value = $l.value + " \$xor " + $r.value; }
	|	^(OP_AND l=pexpression2 r=pexpression2) { $value = $l.value + " \$and " + $r.value; }
	|	^(OP_LEFT l=pexpression2 r=pexpression2) { $value = $l.value + " << " + $r.value; }
	|	^(OP_RIGHT l=pexpression2 r=pexpression2) { $value = $l.value + " >> " + $r.value; }
	|	^(OP_ADD l=pexpression2 r=pexpression2) { $value = $l.value + " + " + $r.value; }
	|	^(OP_SUB l=pexpression2 r=pexpression2) { $value = $l.value + " - " + $r.value; }
	|	^(OP_MULT l=pexpression2 r=pexpression2) { $value = $l.value + " * " + $r.value; }
	|	^(OP_DIV l=pexpression2 r=pexpression2) { $value = $l.value + " / " + $r.value; }

	|	^(OP_NEGATE l=pexpression2) { $value = "-" + $l.value; }
	|	^(OP_INVERT l=pexpression2) { $value = "~" + $l.value; }

	|	^(OP_APPLY n=identifier o=pexpression2_operands) { $value = $n.value + "(" + $o.value + ")"; }
	|	n=identifier { $value = $n.value; }
	|	i=integer { $value = $i.value; }
	|	^(OP_PARENTHESIZED l=pexpression2) { $value = "(" + $l.value + ")"; }
	;

pexpression2_operands returns [String value]
@init { String comma = ""; $value = ""; }
	:	(e=pexpression2 { $value += comma + $e.value; comma = ","; })*
	;

contextblock
	:	^(OP_CONTEXT_BLOCK { ot("[ "); } statements { ot(" ]"); })
	|	OP_NO_CONTEXT_BLOCK
	;

semantic
	:	^(OP_SEMANTIC { out("{"); } code_block { out("}"); } )
	;

code_block
	:	statements
	|	OP_NOP
	;

statements
	:	( { ot("  "); } statement)*
	;

label returns [String value]
	:	^(OP_LABEL n=variable) { $value = "<" + $n.value + ">"; }
	;

section_label returns [String value]
	:	^(OP_SECTION_LABEL n=variable) { $value = "<<" + $n.value + ">>"; }
	;

statement
	:	assignment
	|	declaration
	|	funcall
	|	build_stmt
	|	crossbuild_stmt
	|	goto_stmt
	|	cond_stmt
	|	call_stmt
	|	export
	|	return_stmt
	|	l=label { out($l.value); }
	|	s=section_label { out($s.value); }
	;

assignment
	:	^(OP_ASSIGN l=lvalue e=expr) { out($l.value + " = " + $e.value + ";"); }
	|	^(OP_LOCAL OP_ASSIGN l=lvalue e=expr) { out("local " + $l.value + " = " + $e.value + ";"); }
	;

declaration
	:	^(OP_LOCAL v=variable a=constant) { out("local " + $v.value + ":" + $a.value + ";"); }
	|	^(OP_LOCAL v=variable)            { out("local " + $v.value + ";"); }
	;

lvalue returns [String value]
	:	b=bitrange { $value = $b.value; }
	|	^(OP_DECLARATIVE_SIZE v=variable c=constant) { $value = $v.value + ":" + $c.value; }
	|	v=variable { $value = $v.value; }
	|	s=sizedstar { $value = $s.value; }
	;

bitrange returns [String value]
	:	^(OP_BITRANGE v=variable a=constant b=constant) { $value = $v.value + "[" + $a.value + "," + $b.value + "]"; }
	;

sizedstar returns [String value]
	:	^(OP_DEREFERENCE v=variable c=constant e=expr) { $value = "*[" + $v.value + "]:" + $c.value + " " + $e.value; }
	|	^(OP_DEREFERENCE v=variable e=expr) { $value = "*[" + $v.value + "] " + $e.value; }
	|	^(OP_DEREFERENCE c=constant e=expr) { $value = "*:" + $c.value + " " + $e.value; }
	|	^(OP_DEREFERENCE e=expr) { $value = "* " + $e.value; }
	;

funcall
	:	e=expr_apply { out($e.value + ";"); }
	;

build_stmt
	:	^(OP_BUILD v=variable) { out("build " + $v.value + ";"); }
	;

crossbuild_stmt
	:	^(OP_CROSSBUILD v=varnode n=variable) { out("crossbuild " + $v.value + ", " + $n.value + ";"); }
	;

goto_stmt
	:	^(OP_GOTO j=jumpdest) { out("goto " + $j.value + ";"); }
	;

jumpdest returns [String value]
	:	^(OP_JUMPDEST_SYMBOL v=variable) { $value = $v.value; }
	|	^(OP_JUMPDEST_DYNAMIC e=expr) { $value = "[" + $e.value + "]"; }
	|	^(OP_JUMPDEST_ABSOLUTE i=integer) { $value = $i.value; }
	|	^(OP_JUMPDEST_RELATIVE c=constant v=variable) { $value = $c.value + "[" + $v.value + "]"; }
	|	^(OP_JUMPDEST_LABEL l=label) { $value = $l.value; }
	;

cond_stmt
	:	^(OP_IF e=expr { ot("if (" + $e.value + ") "); } goto_stmt)
	;

call_stmt
	:	^(OP_CALL j=jumpdest) { out("call " + $j.value + ";"); }
	;

return_stmt
	:	^(OP_RETURN e=expr) { out("return [" + $e.value + "];"); }
	|	OP_RETURN { out("return;"); }
	;

export
	:	^(OP_EXPORT e=expr) { out("export " + $e.value + ";"); }
	;

expr returns [String value]
	:	^(OP_BOOL_OR l=expr r=expr) { $value = $l.value + " || " + $r.value; }
	|	^(OP_BOOL_XOR l=expr r=expr) { $value = $l.value + " ^^ " + $r.value; }
	|	^(OP_BOOL_AND l=expr r=expr) { $value = $l.value + " && " + $r.value; }

	|	^(OP_OR l=expr r=expr) { $value = $l.value + " | " + $r.value; }
	|	^(OP_XOR l=expr r=expr) { $value = $l.value + " ^ " + $r.value; }
	|	^(OP_AND l=expr r=expr) { $value = $l.value + " & " + $r.value; }

	|	^(OP_EQUAL l=expr r=expr) { $value = $l.value + " == " + $r.value; }
	|	^(OP_NOTEQUAL l=expr r=expr) { $value = $l.value + " != " + $r.value; }
	|	^(OP_FEQUAL l=expr r=expr) { $value = $l.value + " f== " + $r.value; }
	|	^(OP_FNOTEQUAL l=expr r=expr) { $value = $l.value + " f!= " + $r.value; }

	|	^(OP_LESS l=expr r=expr) { $value = $l.value + " < " + $r.value; }
	|	^(OP_GREATEQUAL l=expr r=expr) { $value = $l.value + " >= " + $r.value; }
	|	^(OP_LESSEQUAL l=expr r=expr) { $value = $l.value + " <= " + $r.value; }
	|	^(OP_GREAT l=expr r=expr) { $value = $l.value + " > " + $r.value; }
	|	^(OP_SLESS l=expr r=expr) { $value = $l.value + " s< " + $r.value; }
	|	^(OP_SGREATEQUAL l=expr r=expr) { $value = $l.value + " s>= " + $r.value; }
	|	^(OP_SLESSEQUAL l=expr r=expr) { $value = $l.value + " s<= " + $r.value; }
	|	^(OP_SGREAT l=expr r=expr) { $value = $l.value + " s> " + $r.value; }
	|	^(OP_FLESS l=expr r=expr) { $value = $l.value + " f< " + $r.value; }
	|	^(OP_FGREATEQUAL l=expr r=expr) { $value = $l.value + " f>= " + $r.value; }
	|	^(OP_FLESSEQUAL l=expr r=expr) { $value = $l.value + " f<= " + $r.value; }
	|	^(OP_FGREAT l=expr r=expr) { $value = $l.value + " f> " + $r.value; }

	|	^(OP_LEFT l=expr r=expr) { $value = $l.value + " << " + $r.value; }
	|	^(OP_RIGHT l=expr r=expr) { $value = $l.value + " >> " + $r.value; }
	|	^(OP_SRIGHT l=expr r=expr) { $value = $l.value + " s>> " + $r.value; }

	|	^(OP_ADD l=expr r=expr) { $value = $l.value + " + " + $r.value; }
	|	^(OP_SUB l=expr r=expr) { $value = $l.value + " - " + $r.value; }
	|	^(OP_FADD l=expr r=expr) { $value = $l.value + " f+ " + $r.value; }
	|	^(OP_FSUB l=expr r=expr) { $value = $l.value + " f- " + $r.value; }

	|	^(OP_MULT l=expr r=expr) { $value = $l.value + " * " + $r.value; }
		|	^(OP_DIV l=expr r=expr) { $value = $l.value + " / " + $r.value; }
	|	^(OP_REM l=expr r=expr) { $value = $l.value + " \% " + $r.value; }
	|	^(OP_SDIV l=expr r=expr) { $value = $l.value + " s/ " + $r.value; }
	|	^(OP_SREM l=expr r=expr) { $value = $l.value + " s\% " + $r.value; }
	|	^(OP_FMULT l=expr r=expr) { $value = $l.value + " f* " + $r.value; }
	|	^(OP_FDIV l=expr r=expr) { $value = $l.value + " f/ " + $r.value; }

	|	^(OP_NOT l=expr) { $value = "!" + $l.value; }
	|	^(OP_INVERT l=expr) { $value = "~" + $l.value; }
	|	^(OP_NEGATE l=expr) { $value = "-" + $l.value; }
	|	^(OP_FNEGATE l=expr) { $value = "f- " + $l.value; }
	|	s=sizedstar { $value = $s.value; }

	|	a=expr_apply { $value = $a.value; }
	|	v=varnode { $value = $v.value; }
	|	b=bitrange { $value = $b.value; }
	|	^(OP_PARENTHESIZED l=expr) { $value = "(" + $l.value + ")"; }
	|	^(OP_BITRANGE2 n=identifier i=integer) { $value = $n.value + ":" + $i.value; }
	;

expr_apply returns [String value]
	:	^(OP_APPLY n=identifier o=expr_operands) { $value = $n.value + "(" + $o.value + ")"; }
	;

expr_operands returns [String value]
	@init {
		String comma = "";
		$value = "";
	}
	:	(e=expr { $value += comma + $e.value; comma = ","; })*
	;

varnode returns [String value]
	:	s=symbol { $value = $s.value; }
	|	^(OP_TRUNCATION_SIZE s=symbol c=constant) { $value = $s.value + ":" + $c.value; }
	|	^(OP_ADDRESS_OF ^(OP_SIZING_SIZE c=constant) v=varnode) { $value = "&:" + $c.value + " " + $v.value; }
	|	^(OP_ADDRESS_OF v=varnode) { $value = "&" + " " + $v.value; }
	;

symbol returns [String value]
	:	n=identifier {$value = $n.value; }
	|	i=integer { $value = $i.value; }
	;

variable returns [String value]
	:	n=identifier { $value = $n.value; }
	;

constant returns [String value]
	:	i=integer { $value = $i.value; }
	;

qstring returns [String value]
	:	^(OP_QSTRING s=.) { $value = "\"" + $s.getText() + "\""; }
	;

identifier returns [String value]
	:	^(OP_IDENTIFIER s=.) { $value = $s.getText(); }
	|	OP_WILDCARD { $value = "_"; }
	;

integer returns [String value]
	:	^(OP_HEX_CONSTANT s=.) { $value = $s.getText(); }
	|	^(OP_DEC_CONSTANT s=.) { $value = $s.getText(); }
	|	^(OP_BIN_CONSTANT s=.) { $value = $s.getText(); }
	;
