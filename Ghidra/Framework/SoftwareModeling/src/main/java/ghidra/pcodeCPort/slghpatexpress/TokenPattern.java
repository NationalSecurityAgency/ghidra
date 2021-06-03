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
package ghidra.pcodeCPort.slghpatexpress;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.context.Token;
import ghidra.pcodeCPort.slghpattern.*;
import ghidra.sleigh.grammar.Location;

public class TokenPattern {
	public final Location location;

	private Pattern pattern;
	private VectorSTL<Token> toklist = new VectorSTL<Token>();
	private boolean leftell;
	private boolean rightell;

	private TokenPattern(Location location, Pattern pat) {
		this.location = location;
		pattern = pat;
		setLeftEllipsis(false);
		setRightEllipsis(false);
	}

	public void dispose() {
		pattern.dispose();
	}

	public void setLeftEllipsis(boolean val) {
		leftell = val;
	}

	public void setRightEllipsis(boolean val) {
		rightell = val;
	}

	public boolean getLeftEllipsis() {
		return leftell;
	}

	public boolean getRightEllipsis() {
		return rightell;
	}

	public Pattern getPattern() {
		return pattern;
	}

	public boolean alwaysTrue() {
		return pattern.alwaysTrue();
	}

	public boolean alwaysFalse() {
		return pattern.alwaysFalse();
	}

	public boolean alwaysInstructionTrue() {
		return pattern.alwaysInstructionTrue();
	}

	// Use the token lists to decide how the two patterns
	// should be aligned relative to each other
	// return how much -tok2- needs to be shifted
	// and set the resulting tokenlist and ellipses
	private static int calls = 0;

	private int resolveTokens(TokenPattern tok1, TokenPattern tok2) {
		calls++;
		boolean reversedirection = false;
		setLeftEllipsis(false);
		setRightEllipsis(false);
		int ressa = 0;
		int minsize =
			tok1.toklist.size() < tok2.toklist.size() ? tok1.toklist.size() : tok2.toklist.size();
		if (minsize == 0) {
			// Check if pattern doesn't care about tokens
			if ((tok1.toklist.size() == 0) && (tok1.getLeftEllipsis() == false) &&
				(tok1.getRightEllipsis() == false)) {
				toklist = tok2.toklist.copy();
				setLeftEllipsis(tok2.getLeftEllipsis());
				setRightEllipsis(tok2.getRightEllipsis());
				return 0;
			}
			else if ((tok2.toklist.size() == 0) && (tok2.getLeftEllipsis() == false) &&
				(tok2.getRightEllipsis() == false)) {
				toklist = tok1.toklist.copy();
				setLeftEllipsis(tok1.getLeftEllipsis());
				setRightEllipsis(tok1.getRightEllipsis());
				return 0;
			}
			// If one of the ellipses is true then the pattern
			// still cares about tokens even though none are
			// specified
		}

		if (tok1.getLeftEllipsis()) {
			reversedirection = true;
			if (tok2.getRightEllipsis()) {
				throw new SleighError("Right/left ellipsis", location);
			}
			else if (tok2.getLeftEllipsis()) {
				setLeftEllipsis(true);
			}
			else if (tok1.toklist.size() != minsize) {
				throw new SleighError(String.format("Mismatched pattern sizes -- %d vs %d",
					tok1.toklist.size(), minsize), location);
			}
			else if (tok1.toklist.size() == tok2.toklist.size()) {
				throw new SleighError("Pattern size cannot vary (missing ... ?)", location);
			}
		}
		else if (tok1.getRightEllipsis()) {
			if (tok2.getLeftEllipsis()) {
				throw new SleighError("Left/right ellipsis", location);
			}
			else if (tok2.getRightEllipsis()) {
				setRightEllipsis(true);
			}
			else if (tok1.toklist.size() != minsize) {
				throw new SleighError(String.format("Mismatched pattern sizes -- %d vs %d",
					tok1.toklist.size(), minsize), location);
			}
			else if (tok1.toklist.size() == tok2.toklist.size()) {
				throw new SleighError("Pattern size cannot vary (missing ... ?)", location);
			}
		}
		else {
			if (tok2.getLeftEllipsis()) {
				reversedirection = true;
				if (tok2.toklist.size() != minsize) {
					throw new SleighError(String.format("Mismatched pattern sizes -- %d vs %d",
						tok2.toklist.size(), minsize), location);
				}
				else if (tok1.toklist.size() == tok2.toklist.size()) {
					throw new SleighError("Pattern size cannot vary (missing ... ?)", location);
				}
			}
			else if (tok2.getRightEllipsis()) {
				if (tok2.toklist.size() != minsize) {
					throw new SleighError(String.format("Mismatched pattern sizes -- %d vs %d",
						tok1.toklist.size(), minsize), location);
				}
				else if (tok1.toklist.size() == tok2.toklist.size()) {
					throw new SleighError("Pattern size cannot vary (missing ... ?)", location);
				}
			}
			else {
				if (tok2.toklist.size() != tok1.toklist.size()) {
					throw new SleighError(String.format("Mismatched pattern sizes -- %d vs %d",
						tok2.toklist.size(), tok1.toklist.size()), location);
				}
			}
		}
		if (reversedirection) {
			for (int i = 0; i < minsize; ++i) {
				if (tok1.toklist.get(tok1.toklist.size() - 1 - i) != tok2.toklist.get(tok2.toklist.size() -
					1 - i)) {
					throw new SleighError("Mismatched tokens when combining patterns", location);
				}
			}
			if (tok1.toklist.size() <= tok2.toklist.size()) {
				for (int i = minsize; i < tok2.toklist.size(); ++i) {
					ressa += tok2.toklist.get(tok2.toklist.size() - 1 - i).getSize();
				}
			}
			else {
				for (int i = minsize; i < tok1.toklist.size(); ++i) {
					ressa += tok1.toklist.get(tok1.toklist.size() - 1 - i).getSize();
				}
			}
			if (tok1.toklist.size() < tok2.toklist.size()) {
				ressa = -ressa;
			}
		}
		else {
			for (int i = 0; i < minsize; ++i) {
				if (!tok1.toklist.get(i).equals(tok2.toklist.get(i))) {
					throw new SleighError("Mismatched tokens when combining patterns", location);
				}
			}
		}
		// Save the results into -this-
		if (tok1.toklist.size() <= tok2.toklist.size()) {
			toklist = tok2.toklist.copy();
		}
		else {
			toklist = tok1.toklist.copy();
		}
		return ressa;
	}

	// Create a mask/value pattern within a single word
	// The field is given by the bitrange [startbit,endbit]
	// bit 0 is the MOST sig bit of the word
	// use the least sig bits of byteval to fill in
	// the field's value
	private static PatternBlock buildSingle(int startbit, int endbit, int byteval) {
		int offset = 0;
		int size = endbit - startbit + 1;
		while (startbit >= 8) {
			offset += 1;
			startbit -= 8;
			endbit -= 8;
		}
		int mask = -1 << (32 - size);
		byteval = (byteval << (32 - size)) & mask;
		mask >>>= startbit;
		byteval >>>= startbit;
		return new PatternBlock(offset, mask, byteval);
	}

	// Build pattern block given a bigendian contiguous
	// range of bits and a value for those bits
	private static PatternBlock buildBigBlock(int size, int bitstart, int bitend, long value) {

		int startbit = 8 * size - 1 - bitend;
		int endbit = 8 * size - 1 - bitstart;

		PatternBlock block = null;
		while (endbit >= startbit) {
			int tmpstart = endbit - (endbit & 7);
			if (tmpstart < startbit) {
				tmpstart = startbit;
			}
			PatternBlock tmpblock = buildSingle(tmpstart, endbit, (int) value);
			if (block == null) {
				block = tmpblock;
			}
			else {
				PatternBlock newblock = block.intersect(tmpblock);
				block.dispose();
				tmpblock.dispose();
				block = newblock;
			}
			value >>>= (endbit - tmpstart + 1);
			endbit = tmpstart - 1;
		}
		return block;
	}

	// Build pattern block given a littleendian contiguous
	// range of bits and a value for those bits
	public static PatternBlock buildLittleBlock(int size, int bitstart, int bitend, long value) {
		int startbit, endbit;

		PatternBlock block = null;

		// we need to convert a bit range specified on a little endian token where the
		// bit indices label the least sig bit as 0 into a bit range on big endian bytes
		// where the indices label the most sig bit as 0. The reversal due to
		// little.big endian cancels part of the reversal due to least.most sig bit
		// labelling, but not on the lower 3 bits. So the transform becomes
		// leave the upper bits the same, but transform the lower 3-bit value x into 7-x.

		startbit = (bitstart / 8) * 8; // Get the high-order portion of little/LSB labelling
		endbit = (bitend / 8) * 8;
		bitend = bitend % 8; // Get the low-order portion of little/LSB labelling
		bitstart = bitstart % 8;

		if (startbit == endbit) {
			startbit += 7 - bitend;
			endbit += 7 - bitstart;
			block = buildSingle(startbit, endbit, (int) value);
		}
		else {
			block = buildSingle(startbit, startbit + (7 - bitstart), (int) value);
			value >>>= (8 - bitstart); // Cut off bits we just encoded
			startbit += 8;
			while (startbit < endbit) {
				PatternBlock tmpblock = buildSingle(startbit, startbit + 7, (int) value);
				if (block == null) {
					block = tmpblock;
				}
				else {
					PatternBlock newblock = block.intersect(tmpblock);
					block.dispose();
					tmpblock.dispose();
					block = newblock;
				}
				value >>>= 8;
				startbit += 8;
			}
			PatternBlock tmpblock = buildSingle(endbit + (7 - bitend), endbit + 7, (int) value);
			if (block == null) {
				block = tmpblock;
			}
			else {
				PatternBlock newblock = block.intersect(tmpblock);
				block.dispose();
				tmpblock.dispose();
				block = newblock;
			}
		}
		return block;
	}

	public TokenPattern(Location location) {
		this.location = location;
		setLeftEllipsis(false);
		setRightEllipsis(false);
		pattern = new InstructionPattern(true);
	}

	public TokenPattern(Location location, boolean tf) { // TRUE or FALSE pattern
		this.location = location;
		setLeftEllipsis(false);
		setRightEllipsis(false);
		pattern = new InstructionPattern(tf);
	}

	TokenPattern(Location location, Token tok) {
		this.location = location;
		setLeftEllipsis(false);
		setRightEllipsis(false);
		pattern = new InstructionPattern(true);
		toklist.push_back(tok);
	}

	// A basic instruction pattern
	public TokenPattern(Location location, Token tok, long value, int bitstart, int bitend) {
		this.location = location;
		toklist.push_back(tok);
		setLeftEllipsis(false);
		setRightEllipsis(false);
		PatternBlock block;

		if (tok.isBigEndian()) {
			block = buildBigBlock(tok.getSize(), bitstart, bitend, value);
		}
		else {
			block = buildLittleBlock(tok.getSize(), bitstart, bitend, value);
		}
		pattern = new InstructionPattern(block);
	}

	public TokenPattern(Location location, long value, int startbit, int endbit) { // A basic context pattern
		this.location = location;
		setLeftEllipsis(false);
		setRightEllipsis(false);
		PatternBlock block;
		int size = (endbit / 8) + 1;

		block = buildBigBlock(size, size * 8 - 1 - endbit, size * 8 - 1 - startbit, value);
		pattern = new ContextPattern(block);
	}

	public TokenPattern(Location location, TokenPattern tokpat) {
		this.location = location;
		simplifyPattern(tokpat);
		toklist = new VectorSTL<Token>(tokpat.toklist);
		setLeftEllipsis(tokpat.getLeftEllipsis());
		setRightEllipsis(tokpat.getRightEllipsis());
	}

	public TokenPattern copyInto(TokenPattern tokpat) {
		pattern.dispose();

		simplifyPattern(tokpat);
		toklist = new VectorSTL<Token>(tokpat.toklist);
		setLeftEllipsis(tokpat.getLeftEllipsis());
		setRightEllipsis(tokpat.getRightEllipsis());
		return this;
	}

	private void simplifyPattern(TokenPattern tokpat) {
		pattern = tokpat.pattern.simplifyClone();
	}

	public void simplifyPattern() {
		simplifyPattern(this);
	}

	// Return -this- AND tokpat
	public TokenPattern doAnd(TokenPattern tokpat) {
		TokenPattern res = new TokenPattern(location, (Pattern) null);
		int sa = res.resolveTokens(this, tokpat);

		res.pattern = pattern.doAnd(tokpat.pattern, sa);
		return res;
	}

	// Return -this- OR tokpat
	public TokenPattern doOr(TokenPattern tokpat) {
		TokenPattern res = new TokenPattern(location, (Pattern) null);
		int sa = res.resolveTokens(this, tokpat);

		res.pattern = pattern.doOr(tokpat.pattern, sa);
		return res;
	}

	public TokenPattern doCat(TokenPattern tokpat) { // Return Concatenation of -this- and
														// -tokpat-
		TokenPattern res = new TokenPattern(location, (Pattern) null);
		int sa;

		res.setLeftEllipsis(getLeftEllipsis());
		res.setRightEllipsis(getRightEllipsis());
		res.toklist = toklist.copy();
		if (getRightEllipsis() || tokpat.getLeftEllipsis()) { // Check for interior ellipsis
			if (getRightEllipsis()) {
				if (!tokpat.alwaysInstructionTrue()) {
					throw new SleighError("Interior ellipsis in pattern", location);
				}
			}
			if (tokpat.getLeftEllipsis()) {
				if (!alwaysInstructionTrue()) {
					throw new SleighError("Interior ellipsis in pattern", location);
				}
				res.setLeftEllipsis(true);
			}
			sa = -1;
		}
		else {
			sa = 0;
			IteratorSTL<Token> iter;
			for (iter = toklist.begin(); !iter.isEnd(); iter.increment()) {
				sa += iter.get().getSize();
			}
			for (iter = tokpat.toklist.begin(); !iter.isEnd(); iter.increment()) {
				res.toklist.push_back(iter.get());
			}
			res.setRightEllipsis(tokpat.getRightEllipsis());
		}
		if (res.getRightEllipsis() && res.getLeftEllipsis()) {
			throw new SleighError("Double ellipsis in pattern", location);
		}
		if (sa < 0) {
			res.pattern = pattern.doAnd(tokpat.pattern, 0);
		}
		else {
			res.pattern = pattern.doAnd(tokpat.pattern, sa);
		}
		return res;
	}

	// Construct pattern that matches anything
	// that matches either -this- or -tokpat-
	public TokenPattern commonSubPattern(TokenPattern tokpat) {
		TokenPattern patres = new TokenPattern(location, (Pattern) null); // Empty shell
		int i;
		boolean reversedirection = false;

		if (getLeftEllipsis() || tokpat.getLeftEllipsis()) {
			if (getRightEllipsis() || tokpat.getRightEllipsis()) {
				throw new SleighError("Right/left ellipsis in commonSubPattern", location);
			}
			reversedirection = true;
		}

		// Find common subset of tokens and ellipses
		patres.setLeftEllipsis(getLeftEllipsis() || tokpat.getLeftEllipsis());
		patres.setRightEllipsis(getRightEllipsis() || tokpat.getRightEllipsis());
		int minnum = toklist.size();
		int maxnum = tokpat.toklist.size();
		if (maxnum < minnum) {
			int tmp = minnum;
			minnum = maxnum;
			maxnum = tmp;
		}
		if (reversedirection) {
			for (i = 0; i < minnum; ++i) {
				Token tok = toklist.get(toklist.size() - 1 - i);
				if (tok.equals(tokpat.toklist.get(tokpat.toklist.size() - 1 - i))) {
					patres.toklist.insert(patres.toklist.begin(), tok);
				}
				else {
					break;
				}
			}
			if (i < maxnum) {
				patres.setLeftEllipsis(true);
			}
		}
		else {
			for (i = 0; i < minnum; ++i) {
				Token tok = toklist.get(i);
				if (tok.equals(tokpat.toklist.get(i))) {
					patres.toklist.push_back(tok);
				}
				else {
					break;
				}
			}
			if (i < maxnum) {
				patres.setRightEllipsis(true);
			}
		}

		patres.pattern = pattern.commonSubPattern(tokpat.pattern, 0);
		return patres;
	}

	// Add up length of concatenated tokens
	public int getMinimumLength() {
		int length = 0;
		for (int i = 0; i < toklist.size(); ++i) {
			length += toklist.get(i).getSize();
		}
		return length;
	}

}
