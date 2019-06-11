/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the &quot;License&quot;);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an &quot;AS IS&quot; BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.xtext.sleigh.formatting2

import com.google.common.base.Strings
import com.google.inject.Inject
import ghidra.xtext.sleigh.services.SleighGrammarAccess
import ghidra.xtext.sleigh.sleigh.DefineTest
import ghidra.xtext.sleigh.sleigh.Expression
import ghidra.xtext.sleigh.sleigh.MACROPARAMSYM
import ghidra.xtext.sleigh.sleigh.Model
import ghidra.xtext.sleigh.sleigh.NAMESYM
import ghidra.xtext.sleigh.sleigh.OPERANDSYM
import ghidra.xtext.sleigh.sleigh.USEROPSYM
import ghidra.xtext.sleigh.sleigh.aligndef
import ghidra.xtext.sleigh.sleigh.anystringlist
import ghidra.xtext.sleigh.sleigh.anystringpart
import ghidra.xtext.sleigh.sleigh.anysymbol
import ghidra.xtext.sleigh.sleigh.assignSym
import ghidra.xtext.sleigh.sleigh.atomic
import ghidra.xtext.sleigh.sleigh.baseconstructor
import ghidra.xtext.sleigh.sleigh.bitrangedef
import ghidra.xtext.sleigh.sleigh.bitrangelist
import ghidra.xtext.sleigh.sleigh.bitrangesingle
import ghidra.xtext.sleigh.sleigh.constraint
import ghidra.xtext.sleigh.sleigh.constraintAdd
import ghidra.xtext.sleigh.sleigh.constraintAnd
import ghidra.xtext.sleigh.sleigh.constraintDiv
import ghidra.xtext.sleigh.sleigh.constraintInvert
import ghidra.xtext.sleigh.sleigh.constraintLeft
import ghidra.xtext.sleigh.sleigh.constraintMult
import ghidra.xtext.sleigh.sleigh.constraintNegate
import ghidra.xtext.sleigh.sleigh.constraintOr
import ghidra.xtext.sleigh.sleigh.constraintRight
import ghidra.xtext.sleigh.sleigh.constraintSinglePexpression
import ghidra.xtext.sleigh.sleigh.constraintSub
import ghidra.xtext.sleigh.sleigh.constraintXor
import ghidra.xtext.sleigh.sleigh.constructprint
import ghidra.xtext.sleigh.sleigh.contextDefs
import ghidra.xtext.sleigh.sleigh.contextblock
import ghidra.xtext.sleigh.sleigh.contextdef
import ghidra.xtext.sleigh.sleigh.contextentry
import ghidra.xtext.sleigh.sleigh.contextfielddef
import ghidra.xtext.sleigh.sleigh.contextlist
import ghidra.xtext.sleigh.sleigh.elleqRight
import ghidra.xtext.sleigh.sleigh.endiandef
import ghidra.xtext.sleigh.sleigh.exportStmt
import ghidra.xtext.sleigh.sleigh.exportedSym
import ghidra.xtext.sleigh.sleigh.exprAnd
import ghidra.xtext.sleigh.sleigh.exprBoolAnd
import ghidra.xtext.sleigh.sleigh.exprBoolOr
import ghidra.xtext.sleigh.sleigh.exprBoolXor
import ghidra.xtext.sleigh.sleigh.exprDiv
import ghidra.xtext.sleigh.sleigh.exprEqual
import ghidra.xtext.sleigh.sleigh.exprFAdd
import ghidra.xtext.sleigh.sleigh.exprFDiv
import ghidra.xtext.sleigh.sleigh.exprFEqual
import ghidra.xtext.sleigh.sleigh.exprFGt
import ghidra.xtext.sleigh.sleigh.exprFGtEqual
import ghidra.xtext.sleigh.sleigh.exprFLess
import ghidra.xtext.sleigh.sleigh.exprFLessEqual
import ghidra.xtext.sleigh.sleigh.exprFMult
import ghidra.xtext.sleigh.sleigh.exprFNegate
import ghidra.xtext.sleigh.sleigh.exprFNotEqual
import ghidra.xtext.sleigh.sleigh.exprFSub
import ghidra.xtext.sleigh.sleigh.exprGt
import ghidra.xtext.sleigh.sleigh.exprGtEqual
import ghidra.xtext.sleigh.sleigh.exprLeft
import ghidra.xtext.sleigh.sleigh.exprLess
import ghidra.xtext.sleigh.sleigh.exprLoad
import ghidra.xtext.sleigh.sleigh.exprLtEqual
import ghidra.xtext.sleigh.sleigh.exprMinus
import ghidra.xtext.sleigh.sleigh.exprMult
import ghidra.xtext.sleigh.sleigh.exprNegate
import ghidra.xtext.sleigh.sleigh.exprNotEqual
import ghidra.xtext.sleigh.sleigh.exprOr
import ghidra.xtext.sleigh.sleigh.exprRem
import ghidra.xtext.sleigh.sleigh.exprRight
import ghidra.xtext.sleigh.sleigh.exprSDiv
import ghidra.xtext.sleigh.sleigh.exprSGt
import ghidra.xtext.sleigh.sleigh.exprSGtEqual
import ghidra.xtext.sleigh.sleigh.exprSLess
import ghidra.xtext.sleigh.sleigh.exprSLtEqual
import ghidra.xtext.sleigh.sleigh.exprSRem
import ghidra.xtext.sleigh.sleigh.exprSRight
import ghidra.xtext.sleigh.sleigh.exprSym
import ghidra.xtext.sleigh.sleigh.exprXor
import ghidra.xtext.sleigh.sleigh.exprrAdd
import ghidra.xtext.sleigh.sleigh.fielddef
import ghidra.xtext.sleigh.sleigh.intblist
import ghidra.xtext.sleigh.sleigh.intbpart
import ghidra.xtext.sleigh.sleigh.integerValue
import ghidra.xtext.sleigh.sleigh.integervarnode
import ghidra.xtext.sleigh.sleigh.jumpdest
import ghidra.xtext.sleigh.sleigh.localDefine
import ghidra.xtext.sleigh.sleigh.macroDefine
import ghidra.xtext.sleigh.sleigh.macroUse
import ghidra.xtext.sleigh.sleigh.macrodef
import ghidra.xtext.sleigh.sleigh.nameattach
import ghidra.xtext.sleigh.sleigh.namesymlist
import ghidra.xtext.sleigh.sleigh.oplist
import ghidra.xtext.sleigh.sleigh.pAnd
import ghidra.xtext.sleigh.sleigh.pNextSet
import ghidra.xtext.sleigh.sleigh.pOr
import ghidra.xtext.sleigh.sleigh.paramlist
import ghidra.xtext.sleigh.sleigh.pcodeopdef
import ghidra.xtext.sleigh.sleigh.pequation
import ghidra.xtext.sleigh.sleigh.pexprAdd
import ghidra.xtext.sleigh.sleigh.pexprAnd
import ghidra.xtext.sleigh.sleigh.pexprDiv
import ghidra.xtext.sleigh.sleigh.pexprInvert
import ghidra.xtext.sleigh.sleigh.pexprLeft
import ghidra.xtext.sleigh.sleigh.pexprMult
import ghidra.xtext.sleigh.sleigh.pexprNegate
import ghidra.xtext.sleigh.sleigh.pexprOr
import ghidra.xtext.sleigh.sleigh.pexprRight
import ghidra.xtext.sleigh.sleigh.pexprSub
import ghidra.xtext.sleigh.sleigh.pexprXor
import ghidra.xtext.sleigh.sleigh.printpiece
import ghidra.xtext.sleigh.sleigh.rtlbody
import ghidra.xtext.sleigh.sleigh.rtlmid
import ghidra.xtext.sleigh.sleigh.singlePexpression
import ghidra.xtext.sleigh.sleigh.sizedstar
import ghidra.xtext.sleigh.sleigh.spaceprop
import ghidra.xtext.sleigh.sleigh.statement
import ghidra.xtext.sleigh.sleigh.subconstructor
import ghidra.xtext.sleigh.sleigh.tokendef
import ghidra.xtext.sleigh.sleigh.tokenprop
import ghidra.xtext.sleigh.sleigh.valueattach
import ghidra.xtext.sleigh.sleigh.valuepart
import ghidra.xtext.sleigh.sleigh.valuepartdef
import ghidra.xtext.sleigh.sleigh.valuesymlist
import ghidra.xtext.sleigh.sleigh.varattach
import ghidra.xtext.sleigh.sleigh.vardef
import ghidra.xtext.sleigh.sleigh.vardeflist
import ghidra.xtext.sleigh.sleigh.varlist
import ghidra.xtext.sleigh.sleigh.varnodedef
import ghidra.xtext.sleigh.sleigh.varpart
import ghidra.xtext.sleigh.sleigh.varsymlist
import ghidra.xtext.sleigh.sleigh.xrtl
import org.eclipse.emf.ecore.EObject
import org.eclipse.xtext.formatting2.AbstractFormatter2
import org.eclipse.xtext.formatting2.IFormattableDocument

class SleighFormatter extends AbstractFormatter2 {
	@Inject extension SleighGrammarAccess

	var constructorPrintLenMap = newHashMap("" -> 0)
	var constructorPatternLenMap = newHashMap("" -> 0)
	var constructorContextLenMap = newHashMap("" -> 0)

	def dispatch void format(Model model, extension IFormattableDocument document) {
		constructorPrintLenMap = newHashMap("" -> 0); // map names to printpiece
		constructorPatternLenMap = newHashMap("" -> 0); // map names to pattern len
		constructorContextLenMap = newHashMap("" -> 0); // map names to context len

		var EObject prev;
		for (spec : model.elements) {
			if (prev !== null) {
				if (!spec.class.equals(prev.class) && !(prev instanceof macroDefine)) {
					prev.append[newLines = 2 priority = 2]
				}
			}
			format(spec, document);

			prev = spec;
		}

		// For Debugging formatting
		// println(regionAccess.toString())
		var constructors = model.eAllContents.filter(typeof(subconstructor))
		var lastName = ""
		while (constructors.hasNext()) {
			var constLike = constructors.next()
			var name = constLike.tableName.name
			// TODO: make preference for max IS column
			var is = constLike.print.is

			var printRegion = constLike.print.regionForEObject;
			// if print region is, good
			if (printRegion !== null) {

				var matchLen = 0;
				var matchOffset = 0;
				if (constLike.match.constraints.immediatelyPreceding !== null) {
					var matchRegion = constLike.match.constraints.regionForEObject;
					matchLen = matchRegion.length;
					matchOffset = matchRegion.offset;
				} else {
					var matchRegion = constLike.match.regionForEObject;
					matchLen = matchRegion.length;
					matchOffset = matchRegion.offset;
				}

				var contextLen = 0;
				if (constLike.cblock.immediatelyPreceding !== null) {
					if (constLike.cblock !== null) {
						contextLen = constLike.cblock.regionForEObject.length
					}
				}

				var truncName = stripDigit(name);
				val printMaxLen = constructorPrintLenMap.get(truncName)
				val contextMaxLen = constructorContextLenMap.get(truncName)
				val matchMaxLen = constructorPatternLenMap.get(truncName)

				var printRegionlen = printRegion.length;
				var isprlen = is.regionFor.keyword('is').previousHiddenRegion.length
				if (printRegionlen == 2) {
					 // region is just 'is' empty print piece
					isprlen = 0
					printRegionlen = 1
				}

				var totalLen = name.length + printRegionlen - isprlen
				if (totalLen < printMaxLen) {
					// put the space before the 'is'
					val prLen = totalLen;
					is.prepend[space = Strings.repeat(" ", printMaxLen - prLen + 2)]
					totalLen += (printMaxLen - prLen) + 2;
				} else {
					is.prepend[space = '  ']
					totalLen += 2;
				}
				totalLen += matchLen + contextLen;
				val maxLBLen = printMaxLen + matchMaxLen + contextMaxLen + 2
				if (totalLen < maxLBLen && maxLBLen < 120) {
					val prLen = totalLen
					constLike.getBody().regionFor.keyword("{").prepend [
						priority = 1
						space = Strings.repeat(" ", maxLBLen - prLen + 1)
					]
				} else {
					constLike.getBody().regionFor.keyword("{").prepend[priority = 1 space = ' ']
				}
				// if different subtable name, add 2 newlines
				if (!lastName.equals(truncName)) {
					constLike.prepend[newLines = 2 priority = 1]
				}
				lastName = truncName;
			}
		}

		var baseconstructors = model.eAllContents.filter(typeof(baseconstructor))
		var name = "" // name of BaseConstructors
		val printMaxLen = constructorPrintLenMap.get(name)
		while (baseconstructors.hasNext()) {
			var constLike = baseconstructors.next()
			var is = constLike.print.is
			var printRegion = constLike.print.regionForEObject;
			if (printRegion !== null) {
				var totalLen = name.length + 1 + printRegion.length -
					is.regionFor.keyword('is').previousHiddenRegion.length
				if (totalLen < printMaxLen) {
					// put the space before the 'is'
					val prLen = totalLen;
					is.prepend[space = Strings.repeat(" ", printMaxLen - prLen)]
					totalLen += (printMaxLen - prLen) + 3;
				} else if (totalLen > printMaxLen) {
					is.prepend[space = '  ']
					totalLen += 3;
				}
			}
		}
	}

	def void computePrintLength(String name, constructprint print) {
		var truncName = stripDigit(name);

		// length before the 'is'
		var prLen = constructorPrintLenMap.getOrDefault(truncName, Integer.valueOf(0))
		var is = print.is
		var printRegion = print.regionForEObject;
		var baseLen = 0;
		// if print region is not empty
		if (printRegion !== null) {
			val curPrLen = printRegion.length
			val curPrWhiteSpace = is.regionFor.keyword('is').previousHiddenRegion
			baseLen = name.toString.length + curPrLen - curPrWhiteSpace.length
		}
		if(baseLen > 40) baseLen = 0;
		if(baseLen >= prLen) constructorPrintLenMap.put(truncName, baseLen)
	}

	def stripDigit(String str) {
		var retStr = str;
		while (Character.isDigit(retStr.charAt(retStr.length - 1))) {
			retStr = retStr.substring(0, retStr.length - 1)
		}
		return retStr;
	}

	def void computeMatchLength(String name, pequation match, contextblock context) {
		var truncName = stripDigit(name);

		// length of match pattern
		var allMatchLen = constructorPatternLenMap.getOrDefault(truncName, Integer.valueOf(0))
		if (match === null || match.constraints === null) {
			return; // something wrong with syntax, can't format
		}
		var matchLen = 0;
		var matchOffset = 0;
		if (match.constraints !== null && match.constraints.immediatelyPreceding !== null) {
			var matchRegion = match.constraints.regionForEObject;
			matchLen = matchRegion.length;
			matchOffset = matchRegion.offset;
		} else {
			var matchRegion = match.regionForEObject;
			matchLen = matchRegion.length;
			matchOffset = matchRegion.offset;
		}
		if(matchLen >= allMatchLen) constructorPatternLenMap.put(truncName, matchLen)

		// length of context block
		var allContextLen = constructorContextLenMap.getOrDefault(truncName, Integer.valueOf(0))
		var contextLen = 0;
		if (context !== null && context.immediatelyPreceding !== null) {
			var contextRegion = context.regionForEObject;
			contextLen = contextRegion.length;
			if(matchOffset == 0) contextLen = 0;
		}
		if(contextLen >= allContextLen) constructorContextLenMap.put(truncName, contextLen)
	}

	def dispatch void format(macroDefine macroDefine, extension IFormattableDocument document) {
		macroDefine.definename.format
		macroDefine.tests.format
		macroDefine.sym.format
		for (isDefined : macroDefine.isdefined) {
			isDefined.format
		}
		macroDefine.symref.format
	}

	def dispatch void format(DefineTest definetest, extension IFormattableDocument document) {
		format(definetest.getTest(), document);
		format(definetest.getSymref(), document);
		format(definetest.getIsdefined(), document);
		format(definetest.getAndtest(), document);
		format(definetest.getOrtest(), document);
	}

	def dispatch void format(endiandef endiandef, extension IFormattableDocument document) {
		format(endiandef.getIs_define(), document);
	}

	def dispatch void format(aligndef aligndef, extension IFormattableDocument document) {
		format(aligndef.getAlign(), document);
	}

	def dispatch void format(tokendef tokendef, extension IFormattableDocument document) {
		tokendef.surround[setNewLines(1, 2, 3)]
		format(tokendef.getSize(), document);
		format(tokendef.getFields(), document);
		tokendef.regionFor.keyword(";").prepend[newLine]
	}

	var maxTokenNameLen = 0;
	var maxStartLen = 0;
	var maxEndLen = 0;
	var maxFound = false;
	var maxtag = 0;

	def dispatch void format(tokenprop tokenprop, extension IFormattableDocument document) {
		maxTokenNameLen = 0
		maxStartLen = 0
		maxEndLen = 0
		maxFound = false
		maxtag = 0
		for (EObject tokens : tokenprop.getTokens()) {
			format(tokens, document);
		}
		maxFound = true
		for (EObject tokens : tokenprop.getTokens()) {
			format(tokens, document);
		}
	}

	def dispatch void format(contextdef contextdef, extension IFormattableDocument document) {
		format(contextdef.getFields(), document);
	}

	def dispatch void format(contextDefs contextdefs, extension IFormattableDocument document) {
		maxTokenNameLen = 0
		maxStartLen = 0
		maxEndLen = 0
		maxFound = false
		maxtag = 0
		for (EObject contextDefs : contextdefs.getContextDefs()) {
			format(contextDefs, document);
		}
		maxFound = true
		for (EObject contextDefs : contextdefs.getContextDefs()) {
			format(contextDefs, document);
		}
	}

	def dispatch void format(fielddef fielddef, extension IFormattableDocument document) {
		format(fielddef.getStart(), document);
		format(fielddef.getEnd(), document);
		val len = fielddef.name.length
		val slen = fielddef.start.value.length
		val elen = fielddef.end.value.length
		val hastag = fielddef.signed || fielddef.hex || fielddef.dec;
		if (maxFound) {
			val padlen = maxTokenNameLen - len + 1;
			fielddef.prepend[setNewLines(1, 1, 2)].surround[indent]
			fielddef.regionFor.keyword("=").prepend[space = Strings.repeat(" ", padlen)]
			fielddef.regionFor.keyword("(").append[space = Strings.repeat(" ", maxStartLen - slen)]
			fielddef.regionFor.keyword(",").append[space = Strings.repeat(" ", maxEndLen - elen)].prepend[noSpace]

			if (!hastag) {
				fielddef.regionFor.keyword(")").prepend[noSpace].append[space = Strings.repeat(" ", maxtag + 1)]
			} else {
				fielddef.regionFor.keyword(")").prepend[noSpace]
			}
			fielddef.regionFor.keyword("=").append[space = " "]
			fielddef.regionFor.keyword("signed").prepend[oneSpace]
		} else if (len > maxTokenNameLen) {
			maxTokenNameLen = len
		}
		if (maxStartLen < slen) {
			maxStartLen = slen
		}
		if (maxEndLen < elen) {
			maxEndLen = elen
		}
		if (fielddef.signed) {
			maxtag = 6;
		} else if (fielddef.hex || fielddef.dec) {
			maxtag = 3;
		}
	}

	def dispatch void format(macroUse macrouse, extension IFormattableDocument document) {
		format(macrouse.getDefine(), document);
	}

	def dispatch void format(contextfielddef contextfielddef, extension IFormattableDocument document) {
		format(contextfielddef.getStart(), document);
		format(contextfielddef.getEnd(), document);
		val len = contextfielddef.name.length
		val slen = contextfielddef.start.value.length
		val elen = contextfielddef.end.value.length
		val hastag = contextfielddef.signed || contextfielddef.noflow || contextfielddef.hex || contextfielddef.dec;
		if (maxFound) {
			val padlen = maxTokenNameLen - len + 1;
			contextfielddef.prepend[setNewLines(1, 1, 2)].surround[indent]
			contextfielddef.regionFor.keyword("=").prepend[space = Strings.repeat(" ", padlen)]
			contextfielddef.regionFor.keyword("(").append[space = Strings.repeat(" ", maxStartLen - slen)]
			contextfielddef.regionFor.keyword(",").append[space = Strings.repeat(" ", maxEndLen - elen)].prepend [
				noSpace
			]
			contextfielddef.regionFor.keyword(")").prepend[noSpace]
			contextfielddef.regionFor.keyword("=").append[space = " "]
			contextfielddef.regionFor.keyword("signed").prepend[oneSpace]
			contextfielddef.regionFor.keyword("noflow").prepend[oneSpace]
			if (!hastag) {
				contextfielddef.regionFor.keyword(")").prepend[noSpace].append[space = Strings.repeat(" ", maxtag + 1)]
			} else {
				contextfielddef.regionFor.keyword(")").prepend[noSpace]
			}
		} else if (len > maxTokenNameLen) {
			maxTokenNameLen = len
		}
		if (maxStartLen < slen) {
			maxStartLen = slen
		}
		if (maxEndLen < elen) {
			maxEndLen = elen
		}
		if (contextfielddef.signed || contextfielddef.noflow) {
			maxtag = 6;
		} else if (contextfielddef.hex || contextfielddef.dec) {
			maxtag = 3;
		}
	}

	def dispatch void format(spaceprop spaceprop, extension IFormattableDocument document) {
		format(spaceprop.getSpace(), document);
		format(spaceprop.getSize(), document);
		format(spaceprop.getWordsize(), document);
	}

	def dispatch void format(varnodedef varnodedef, extension IFormattableDocument document) {
		format(varnodedef.getOffset(), document);
		format(varnodedef.getSize(), document);
		format(varnodedef.getVars(), document);
	}

	def dispatch void format(vardeflist vars, extension IFormattableDocument document) {
		for (vardef varDefList : vars.getVarDefList()) {
			format(varDefList, document);
		}
		// format multi-line variable attach definitions
		if (vars.isMultiline) {
			var open = vars.regionFor.keyword('[')
			var close = vars.regionFor.keyword(']')
			interior(open, close)[indent]
			open.append[newLine]
			close.prepend[newLine]
			var vlist = vars.varDefList;
			var maxLen = 0;
			for (v : vlist) {
				var len = 1;
				if (!v.isIsempty) {
					len = v.varname.name.length;
				}
				if (len > maxLen) {
					maxLen = len;
				}
			}
			if(maxLen > 20) maxLen = 20;
			var previousLen = 0;
			for (v : vlist) {
				var len = 1;
				if (!v.isIsempty) {
					len = v.varname.name.length;
				}

				if (v.nextHiddenRegion !== null && v.nextHiddenRegion.isMultiline) {
					v.append[newLine]
				}
				if (previousLen != 0) {
					val prevLen = previousLen
					v.prepend[space = Strings.repeat(" ", prevLen)]
					previousLen = 0
				}
				if (v.isIsempty) {
					previousLen = maxLen - 1 + 1;
				} else if (len < maxLen) {
					val spaceLen = maxLen - len + 1;
					previousLen = spaceLen;
				// v.append[space = Strings.repeat(" ", spaceLen)]
				} else {
					previousLen = 1;
				}
			}
		}
	}

	def dispatch void format(vardef vardef, extension IFormattableDocument document) {
		format(vardef.getVarname(), document);
	}

	def dispatch void format(bitrangedef bitrangedef, extension IFormattableDocument document) {
		format(bitrangedef.getList(), document);
	}

	def dispatch void format(bitrangelist bitrangelist, extension IFormattableDocument document) {
		for (bitrangesingle bitrangeEntries : bitrangelist.getBitrangeEntries()) {
			format(bitrangeEntries, document);
		}
	}

	def dispatch void format(bitrangesingle bitrangesingle, extension IFormattableDocument document) {
		format(bitrangesingle.getStart(), document);
		format(bitrangesingle.getEnd(), document);
	}

	def dispatch void format(pcodeopdef pcodeopdef, extension IFormattableDocument document) {
		for (USEROPSYM ops : pcodeopdef.getOps()) {
			format(ops, document);
		}
		pcodeopdef.regionFor.keyword(";").prepend[noSpace]
//		pcodeopdef.surround[setNewLines(1,2,3)]
	}

	def dispatch void format(valueattach valueattach, extension IFormattableDocument document) {
		format(valueattach.getValuelist(), document);
		format(valueattach.getBlist(), document);
	}

	def dispatch void format(nameattach nameattach, extension IFormattableDocument document) {
		format(nameattach.getValuelist(), document);
		format(nameattach.getSlist(), document);
	}

	def dispatch void format(varattach varattach, extension IFormattableDocument document) {
		format(varattach.getValuelist(), document);
		format(varattach.getVlist(), document);
	}

	def dispatch void format(macrodef macrodef, extension IFormattableDocument document) {
		format(macrodef.getArgs(), document);
		format(macrodef.getBody(), document);
	}

	def dispatch void format(rtlbody rtlbody, extension IFormattableDocument document) {
		var body = rtlbody.getBody();

		if (body !== null) {
			format(body, document);
		}

		var open = rtlbody.regionFor.keyword('{')
		var close = rtlbody.regionFor.keyword('}')
		interior(open, close)[indent priority=3]
				
		if (rtlbody.isMultiline) {
			open.prepend[oneSpace]
			close.prepend[newLine]
		}
		
		if (rtlbody.isUnimpl) {
			rtlbody.prepend[newLine indent priority=3]
		}
	}

	def dispatch void format(baseconstructor baseconstructor, extension IFormattableDocument document) {
		baseconstructor.regionFor.keyword(":").append[noSpace]

		format(baseconstructor.getPrint(), document);
		format(baseconstructor.getMatch(), document);
		format(baseconstructor.cblock, document);
		format(baseconstructor.getBody(), document);

		var allBaseLen = constructorPrintLenMap.getOrDefault("", Integer.valueOf(0))
		var is = baseconstructor.print.is
		var printRegion = baseconstructor.print.regionForEObject;
		// if print region is bad, need to bail
		if (printRegion === null) {
			return
		}
		var baseLen = printRegion.length - is.regionFor.keyword('is').previousHiddenRegion.length
		if(baseLen > 40) baseLen = 0;
		if(baseLen >= allBaseLen) constructorPrintLenMap.put("", baseLen)

	}

	def dispatch void format(subconstructor sub, extension IFormattableDocument document) {
		sub.regionFor.keyword(":").prepend[noSpace]

		//sub.surround[setNewLines(1, 2, 3)]

		format(sub.tableName, document);
		format(sub.print, document);
		format(sub.match, document);
		format(sub.cblock, document);
		format(sub.body, document);

		// format short body, long bodies, force to newline, full formating
		var open = sub.body.regionFor.keyword('{')
		var close = sub.body.regionFor.keyword('}')
		var body = sub.body;
		var bodyLen = 3
		if (open !== null && close !== null) {
			bodyLen = body.regionForEObject.length;
			if (!sub.body.isMultiline) {
				open.prepend[newLines = 0].append[oneSpace]
				close.prepend[oneSpace]
				body.body.statements.rtllist.forEach [
					regionFor.keywords(';').forEach[it.prepend[space = ''].append[space = ' ']]
				]
				body.body.export.regionFor.keywords(';').forEach [
					it.prepend[space = ''].append[space = ' ']
				]
				body.body.statements.rtllist.forEach [
					regionFor.keywords(';').forEach[it.prepend[space = ''].append[space = ' ']]
				]
			} else if (sub.body.body.regionForEObject.length > 0 && sub.body.body.isMultiline) {
				body.body.statements.rtllist.forEach [
					regionFor.keywords(';').forEach [
						if (it.nextHiddenRegion !== null && it.nextHiddenRegion.isMultiline) {
							it.append[newLine]
						} else {
							it.append[space = ' ']
						}
					]
				]
				body.body.export.regionFor.keywords(';').forEach [
					if (it.nextHiddenRegion !== null && it.nextHiddenRegion.isMultiline) {
						it.append[newLine]
					} else {
						it.append[space = ' ']
					}
				]
				body.body.statements.rtllist.forEach [
					if (it.nextHiddenRegion !== null && it.nextHiddenRegion.isMultiline) {
						it.append[newLine]
					} else {
						it.append[space = ' ']
					}
				]
			}
		}

		// length of printpiece
		computePrintLength(sub.tableName.name, sub.print);

		// length of match pattern
		computeMatchLength(sub.tableName.name, sub.match, sub.cblock);
	}

	def dispatch void format(constructprint constructprint, extension IFormattableDocument document) {
		for (printpiece printpieces : constructprint.getPrintpieces()) {
			format(printpieces, document);
		}
		format(constructprint.getIs(), document);
	}

	def dispatch void format(printpiece printpiece, extension IFormattableDocument document) {
		format(printpiece.getSym(), document);
	}

	def dispatch void format(pexprAdd pexpradd, extension IFormattableDocument document) {
		format(pexpradd.getRight(), document);
		format(pexpradd.getLeft(), document);
	}

	def dispatch void format(pexprSub pexprsub, extension IFormattableDocument document) {
		format(pexprsub.getRight(), document);
		format(pexprsub.getLeft(), document);
	}

	def dispatch void format(pexprMult pexprmult, extension IFormattableDocument document) {
		format(pexprmult.getRight(), document);
		format(pexprmult.getLeft(), document);
	}

	def dispatch void format(pexprLeft pexprleft, extension IFormattableDocument document) {
		format(pexprleft.getRight(), document);
		format(pexprleft.getLeft(), document);
	}

	def dispatch void format(pexprRight pexprright, extension IFormattableDocument document) {
		format(pexprright.getRight(), document);
		format(pexprright.getLeft(), document);
	}

	def dispatch void format(pexprAnd pexprand, extension IFormattableDocument document) {
		format(pexprand.getRight(), document);
		format(pexprand.getLeft(), document);
	}

	def dispatch void format(pexprOr pexpror, extension IFormattableDocument document) {
		format(pexpror.getRight(), document);
		format(pexpror.getLeft(), document);
	}

	def dispatch void format(pexprXor pexprxor, extension IFormattableDocument document) {
		format(pexprxor.getRight(), document);
		format(pexprxor.getLeft(), document);
	}

	def dispatch void format(pexprDiv pexprdiv, extension IFormattableDocument document) {
		format(pexprdiv.getRight(), document);
		format(pexprdiv.getLeft(), document);
	}

	def dispatch void format(pexprNegate pexprnegate, extension IFormattableDocument document) {
		format(pexprnegate.getLeft(), document);
	}

	def dispatch void format(pexprInvert pexprinvert, extension IFormattableDocument document) {
		format(pexprinvert.getLeft(), document);
	}

	def dispatch void format(singlePexpression singlepexpression, extension IFormattableDocument document) {
		format(singlepexpression.getIntval(), document);
		format(singlepexpression.getSym(), document);
		format(singlepexpression.getRight(), document);
	}

	def dispatch void format(constraintAdd constraintadd, extension IFormattableDocument document) {
		format(constraintadd.getRight(), document);
		format(constraintadd.getLeft(), document);
	}

	def dispatch void format(constraintSub constraintsub, extension IFormattableDocument document) {
		format(constraintsub.getRight(), document);
		format(constraintsub.getLeft(), document);
	}

	def dispatch void format(constraintMult constraintmult, extension IFormattableDocument document) {
		format(constraintmult.getRight(), document);
		format(constraintmult.getLeft(), document);
	}

	def dispatch void format(constraintLeft constraintleft, extension IFormattableDocument document) {
		format(constraintleft.getRight(), document);
		format(constraintleft.getLeft(), document);
	}

	def dispatch void format(constraintRight constraintright, extension IFormattableDocument document) {
		format(constraintright.getRight(), document);
		format(constraintright.getLeft(), document);
	}

	def dispatch void format(constraintAnd constraintand, extension IFormattableDocument document) {
		format(constraintand.getRight(), document);
		format(constraintand.getLeft(), document);
	}

	def dispatch void format(constraintOr constraintor, extension IFormattableDocument document) {
		format(constraintor.getRight(), document);
		format(constraintor.getLeft(), document);
	}

	def dispatch void format(constraintXor constraintxor, extension IFormattableDocument document) {
		format(constraintxor.getRight(), document);
		format(constraintxor.getLeft(), document);
	}

	def dispatch void format(constraintDiv constraintdiv, extension IFormattableDocument document) {
		format(constraintdiv.getRight(), document);
		format(constraintdiv.getLeft(), document);
	}

	def dispatch void format(constraintNegate constraintnegate, extension IFormattableDocument document) {
		format(constraintnegate.getExpr(), document);
	}

	def dispatch void format(constraintInvert constraintinvert, extension IFormattableDocument document) {
		format(constraintinvert.getExpr(), document);
	}

	def dispatch void format(constraintSinglePexpression constraintsinglepexpression,
		extension IFormattableDocument document) {
		format(constraintsinglepexpression.getIntval(), document);
		format(constraintsinglepexpression.getSym(), document);
		format(constraintsinglepexpression.getRight(), document);
	}

	def dispatch void format(pequation pequation, extension IFormattableDocument document) {
		format(pequation.getConstraints(), document);
	}

	def dispatch void format(pNextSet pnextset, extension IFormattableDocument document) {
		format(pnextset.getRight(), document);
		format(pnextset.getLeft(), document);
	}

	def dispatch void format(pAnd pand, extension IFormattableDocument document) {
		format(pand.getRight(), document);
		format(pand.getLeft(), document);
	}

	def dispatch void format(pOr por, extension IFormattableDocument document) {
		format(por.getRight(), document);
		format(por.getLeft(), document);
	}

	def dispatch void format(atomic atomic, extension IFormattableDocument document) {
		format(atomic.getDefine(), document);
		format(atomic.getRight(), document);
	}

	def dispatch void format(constraint constraint, extension IFormattableDocument document) {
		format(constraint.getValue(), document);
	}

	def dispatch void format(contextblock contextblock, extension IFormattableDocument document) {
		format(contextblock.getBlock(), document);
	}

	def dispatch void format(contextlist contextlist, extension IFormattableDocument document) {
		for (contextentry entry : contextlist.getEntry()) {
			format(entry, document);
		}
	}

	def dispatch void format(contextentry contextentry, extension IFormattableDocument document) {
		format(contextentry.getRhs(), document);
		format(contextentry.getTsym(), document);
	}

	def dispatch void format(OPERANDSYM operandsym, extension IFormattableDocument document) {
		format(operandsym.getRhs(), document);
	}

	def dispatch void format(xrtl xrtl, extension IFormattableDocument document) {
		format(xrtl.getStatements(), document);
		format(xrtl.getExport(), document);
		format(xrtl.getAdditionalStatements(), document);
	}

	def dispatch void format(exportStmt exportstmt, extension IFormattableDocument document) {
		format(exportstmt.getResultsize(), document);
		format(exportstmt.getResult(), document);
	}

	def dispatch void format(exportedSym exportedsym, extension IFormattableDocument document) {
		format(exportedsym.getVarnode(), document);
		format(exportedsym.getSize(), document);
		format(exportedsym.getConst(), document);
	}

	def dispatch void format(rtlmid rtlmid, extension IFormattableDocument document) {
		for (statement rtllist : rtlmid.getRtllist()) {
			format(rtllist, document);
		}
		for (macroUse macro : rtlmid.getMacro()) {
			format(macro, document);
		}
	}

	def dispatch void format(statement statement, extension IFormattableDocument document) {
		statement.prepend[setNewLines(0,1,2)]
		format(statement.getSection_name(), document);
		format(statement.getLhs(), document);
		format(statement.getRhs(), document);
		format(statement.getPtrsize(), document);
		format(statement.getLhsexpr(), document);
		format(statement.getStart(), document);
		format(statement.getEnd(), document);
		format(statement.getCrossvnode(), document);
		format(statement.getDelayslot(), document);
		format(statement.getDest(), document);
		format(statement.getIfexpr(), document);
		format(statement.getGotodest(), document);
		format(statement.getArgs(), document);
		format(statement.getLabel(), document);
	}

	def dispatch void format(assignSym assignsym, extension IFormattableDocument document) {
		format(assignsym.getLocal(), document);
		format(assignsym.getDefine(), document);
	}

	def dispatch void format(localDefine localdefine, extension IFormattableDocument document) {
		format(localdefine.getSym(), document);
		format(localdefine.getSize(), document);
	}

	def dispatch void format(exprrAdd exprradd, extension IFormattableDocument document) {
		format(exprradd.getRight(), document);
		format(exprradd.getLeft(), document);
	}

	def dispatch void format(exprMinus exprminus, extension IFormattableDocument document) {
		format(exprminus.getRight(), document);
		format(exprminus.getLeft(), document);
	}

	def dispatch void format(exprEqual exprequal, extension IFormattableDocument document) {
		format(exprequal.getRight(), document);
		format(exprequal.getLeft(), document);
	}

	def dispatch void format(exprNotEqual exprnotequal, extension IFormattableDocument document) {
		format(exprnotequal.getRight(), document);
		format(exprnotequal.getLeft(), document);
	}

	def dispatch void format(exprLess exprless, extension IFormattableDocument document) {
		format(exprless.getRight(), document);
		format(exprless.getLeft(), document);
	}

	def dispatch void format(exprGtEqual exprgtequal, extension IFormattableDocument document) {
		format(exprgtequal.getRight(), document);
		format(exprgtequal.getLeft(), document);
	}

	def dispatch void format(exprLtEqual exprltequal, extension IFormattableDocument document) {
		format(exprltequal.getRight(), document);
		format(exprltequal.getLeft(), document);
	}

	def dispatch void format(exprGt exprgt, extension IFormattableDocument document) {
		format(exprgt.getRight(), document);
		format(exprgt.getLeft(), document);
	}

	def dispatch void format(exprSLess exprsless, extension IFormattableDocument document) {
		format(exprsless.getRight(), document);
		format(exprsless.getLeft(), document);
	}

	def dispatch void format(exprSGtEqual exprsgtequal, extension IFormattableDocument document) {
		format(exprsgtequal.getRight(), document);
		format(exprsgtequal.getLeft(), document);
	}

	def dispatch void format(exprSLtEqual exprsltequal, extension IFormattableDocument document) {
		format(exprsltequal.getRight(), document);
		format(exprsltequal.getLeft(), document);
	}

	def dispatch void format(exprSGt exprsgt, extension IFormattableDocument document) {
		format(exprsgt.getRight(), document);
		format(exprsgt.getLeft(), document);
	}

	def dispatch void format(exprXor exprxor, extension IFormattableDocument document) {
		format(exprxor.getRight(), document);
		format(exprxor.getLeft(), document);
	}

	def dispatch void format(exprAnd exprand, extension IFormattableDocument document) {
		format(exprand.getRight(), document);
		format(exprand.getLeft(), document);
	}

	def dispatch void format(exprOr expror, extension IFormattableDocument document) {
		format(expror.getRight(), document);
		format(expror.getLeft(), document);
	}

	def dispatch void format(exprLeft exprleft, extension IFormattableDocument document) {
		format(exprleft.getRight(), document);
		format(exprleft.getLeft(), document);
	}

	def dispatch void format(exprRight exprright, extension IFormattableDocument document) {
		format(exprright.getRight(), document);
		format(exprright.getLeft(), document);
	}

	def dispatch void format(exprSRight exprsright, extension IFormattableDocument document) {
		format(exprsright.getRight(), document);
		format(exprsright.getLeft(), document);
	}

	def dispatch void format(exprMult exprmult, extension IFormattableDocument document) {
		format(exprmult.getRight(), document);
		format(exprmult.getLeft(), document);
	}

	def dispatch void format(exprDiv exprdiv, extension IFormattableDocument document) {
		format(exprdiv.getRight(), document);
		format(exprdiv.getLeft(), document);
	}

	def dispatch void format(exprSDiv exprsdiv, extension IFormattableDocument document) {
		format(exprsdiv.getRight(), document);
		format(exprsdiv.getLeft(), document);
	}

	def dispatch void format(exprRem exprrem, extension IFormattableDocument document) {
		format(exprrem.getRight(), document);
		format(exprrem.getLeft(), document);
	}

	def dispatch void format(exprSRem exprsrem, extension IFormattableDocument document) {
		format(exprsrem.getRight(), document);
		format(exprsrem.getLeft(), document);
	}

	def dispatch void format(exprBoolXor exprboolxor, extension IFormattableDocument document) {
		format(exprboolxor.getRight(), document);
		format(exprboolxor.getLeft(), document);
	}

	def dispatch void format(exprBoolAnd exprbooland, extension IFormattableDocument document) {
		format(exprbooland.getRight(), document);
		format(exprbooland.getLeft(), document);
	}

	def dispatch void format(exprBoolOr exprboolor, extension IFormattableDocument document) {
		format(exprboolor.getRight(), document);
		format(exprboolor.getLeft(), document);
	}

	def dispatch void format(exprFEqual exprfequal, extension IFormattableDocument document) {
		format(exprfequal.getRight(), document);
		format(exprfequal.getLeft(), document);
	}

	def dispatch void format(exprFNotEqual exprfnotequal, extension IFormattableDocument document) {
		format(exprfnotequal.getRight(), document);
		format(exprfnotequal.getLeft(), document);
	}

	def dispatch void format(exprFLess exprfless, extension IFormattableDocument document) {
		format(exprfless.getRight(), document);
		format(exprfless.getLeft(), document);
	}

	def dispatch void format(exprFGt exprfgt, extension IFormattableDocument document) {
		format(exprfgt.getRight(), document);
		format(exprfgt.getLeft(), document);
	}

	def dispatch void format(exprFLessEqual exprflessequal, extension IFormattableDocument document) {
		format(exprflessequal.getRight(), document);
		format(exprflessequal.getLeft(), document);
	}

	def dispatch void format(exprFGtEqual exprfgtequal, extension IFormattableDocument document) {
		format(exprfgtequal.getRight(), document);
		format(exprfgtequal.getLeft(), document);
	}

	def dispatch void format(exprFAdd exprfadd, extension IFormattableDocument document) {
		format(exprfadd.getRight(), document);
		format(exprfadd.getLeft(), document);
	}

	def dispatch void format(exprFSub exprfsub, extension IFormattableDocument document) {
		format(exprfsub.getRight(), document);
		format(exprfsub.getLeft(), document);
	}

	def dispatch void format(exprFMult exprfmult, extension IFormattableDocument document) {
		format(exprfmult.getRight(), document);
		format(exprfmult.getLeft(), document);
	}

	def dispatch void format(exprFDiv exprfdiv, extension IFormattableDocument document) {
		format(exprfdiv.getRight(), document);
		format(exprfdiv.getLeft(), document);
	}

	def dispatch void format(exprNegate exprnegate, extension IFormattableDocument document) {
		format(exprnegate.getExpr(), document);
	}

	def dispatch void format(exprFNegate exprfnegate, extension IFormattableDocument document) {
		format(exprfnegate.getExpr(), document);
	}

	def dispatch void format(exprLoad exprload, extension IFormattableDocument document) {
		format(exprload.getLoc(), document);
		format(exprload.getExpr(), document);
	}

	def dispatch void format(Expression expression, extension IFormattableDocument document) {
		format(expression.getVnode(), document);
		format(expression.getRight(), document);
		format(expression.getOp1(), document);
		format(expression.getOp2(), document);
	}

	def dispatch void format(exprSym exprsym, extension IFormattableDocument document) {
		format(exprsym.getSize(), document);
		format(exprsym.getStart(), document);
		format(exprsym.getEnd(), document);
		format(exprsym.getInode(), document);
	}

	def dispatch void format(sizedstar sizedstar, extension IFormattableDocument document) {
		format(sizedstar.getSpace(), document);
		format(sizedstar.getSize(), document);
	}

	def dispatch void format(jumpdest jumpdest, extension IFormattableDocument document) {
		format(jumpdest.getInst_start(), document);
		format(jumpdest.getInst_end(), document);
		format(jumpdest.getConst(), document);
		format(jumpdest.getSpace(), document);
	}

	def dispatch void format(integervarnode integervarnode, extension IFormattableDocument document) {
		format(integervarnode.getReladdr(), document);
		format(integervarnode.getConst(), document);
		format(integervarnode.getSize(), document);
		format(integervarnode.getInode(), document);
	}

	def dispatch void format(intblist intblist, extension IFormattableDocument document) {
		for (intbpart args : intblist.getArgs()) {
			format(args, document);
		}
	}

	def dispatch void format(intbpart intbpart, extension IFormattableDocument document) {
		format(intbpart.getValue(), document);
	}

	def dispatch void format(anystringlist anystringlist, extension IFormattableDocument document) {
		for (anystringpart namelist : anystringlist.getNamelist()) {
			format(namelist, document);
		}
	}

	def dispatch void format(anystringpart anystringpart, extension IFormattableDocument document) {
		format(anystringpart.getSym(), document);
	}

	def dispatch void format(valuesymlist valuesymlist, extension IFormattableDocument document) {
		for (valuepart valuelist : valuesymlist.getValuelist()) {
			format(valuelist, document);
		}
		format(valuesymlist.getValue(), document);
	}

	def dispatch void format(namesymlist namesymlist, extension IFormattableDocument document) {
		for (NAMESYM valuelist : namesymlist.getValuelist()) {
			format(valuelist, document);
		}
		format(namesymlist.getValue(), document);
	}

	def dispatch void format(varsymlist varsymlist, extension IFormattableDocument document) {
		for (valuepartdef valuelist : varsymlist.getValuelist()) {
			format(valuelist, document);
		}
	}

	def dispatch void format(varlist varlist, extension IFormattableDocument document) {
		for (varpart varDefList : varlist.getVarDefList()) {
			format(varDefList, document);
		}
	}

	def dispatch void format(paramlist paramlist, extension IFormattableDocument document) {
		for (Expression parameters : paramlist.getParameters()) {
			format(parameters, document);
		}
	}

	def dispatch void format(oplist oplist, extension IFormattableDocument document) {
		for (MACROPARAMSYM args : oplist.getArgs()) {
			format(args, document);
		}
	}

	def dispatch void format(anysymbol anysymbol, extension IFormattableDocument document) {
		format(anysymbol.getSym(), document);
	}

	def dispatch void format(integerValue integervalue, extension IFormattableDocument document) {
		format(integervalue.getSym(), document);
	}

	def dispatch void format(elleqRight elleqright, extension IFormattableDocument document) {
		format(elleqright.getLeft(), document);
	}
}
