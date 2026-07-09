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
package ghidra.feature.fid.db;

import java.util.Set;

import ghidra.app.util.sourcelanguage.SourceLanguageID;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;

/**
 * A set of program properties that a FID database filters on
 */
public class FidProgramID {
	LanguageID language;			// Ghidra ID of the program (null matches any program)
	CompilerSpecID compiler;		// Compiler spec of the program (null matches any spec)
	Set<SourceLanguageID> sources;	// Source languages of the program (null matches all languages)

	/**
	 * Construct a program id that will match against all databases
	 */
	public FidProgramID() {
		language = null;
		compiler = null;
		sources = null;
	}

	/**
	 * Construct a program id for a specific program. The caller can optionally request
	 * that compiler spec and source language be ignored when querying or ingesting into
	 * a FID database. 
	 * @param program is the specific program
	 * @param ignoreCompilerSpec is true to ignore compiler spec and source language
	 */
	public FidProgramID(Program program, boolean ignoreCompilerSpec) {
		language = program.getLanguageID();
		if (ignoreCompilerSpec) {
			compiler = null;
			sources = null;
		}
		else {
			compiler = program.getCompilerSpec().getCompilerSpecID();
			sources = program.getSourceLanguageIDs();
		}
	}

	/**
	 * Construct id that matches a specific LanguageID and compiler spec
	 * @param lang is the LanguageID to match
	 * @param comp is the compiler spec to match (may be null)
	 * @param src is the set of source languages to match (may be null)
	 */
	public FidProgramID(LanguageID lang, CompilerSpecID comp, Set<SourceLanguageID> src) {
		language = lang;
		compiler = comp;
		sources = src;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof FidProgramID)) {
			return false;
		}
		FidProgramID otherID = (FidProgramID) obj;
		if (language != null) {
			if (!language.equals(otherID.language)) {
				return false;
			}
		}
		else if (otherID.language != null) {
			return false;
		}
		if (compiler != null) {
			if (!compiler.equals(otherID.compiler)) {
				return false;
			}
		}
		else if (otherID.compiler != null) {
			return false;
		}
		if (sources != null) {
			return sources.equals(otherID.sources);
		}
		else if (otherID.sources != null) {
			return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		int res = 0;
		if (language != null) {
			res += language.hashCode();
		}
		if (compiler != null) {
			res += compiler.hashCode();
		}
		if (sources != null) {
			res += sources.hashCode();
		}
		return res;
	}

}
