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
package ghidra.xtext.sleigh.converter;

import java.math.BigInteger;
import java.util.Map;

import org.antlr.runtime.Token;
import org.antlr.runtime.TokenSource;
import org.eclipse.xtext.AbstractRule;
import org.eclipse.xtext.conversion.ValueConverterException;
import org.eclipse.xtext.conversion.impl.AbstractLexerBasedConverter;
import org.eclipse.xtext.nodemodel.INode;
import org.eclipse.xtext.parser.antlr.ITokenDefProvider;
import org.eclipse.xtext.parser.antlr.Lexer;
import org.eclipse.xtext.util.Strings;

import com.google.inject.Provider;

public class IntValueConverter extends AbstractLexerBasedConverter<BigInteger> {
	
	@Override
	protected String toEscapedString(BigInteger value) {
		return value.toString();
	}
	
	@Override
	protected void assertValidValue(BigInteger value) {
		super.assertValidValue(value);
		if (value.compareTo(BigInteger.ZERO) < 0)
			throw new ValueConverterException(getRuleName() + "-value may not be negative (value: " + value + ").", null, null);
	}
	
	public BigInteger toValue(String string, INode node) {
		if (Strings.isEmpty(string))
			throw new ValueConverterException("Couldn't convert empty string to an int value.", node, null);
		try {
			String parseString = string;
			int radix = 10;
			if (parseString.startsWith("0x") || parseString.startsWith("0X")) {
				parseString = string.substring(2);
				radix=16;
			}
			if (parseString.startsWith("0b") || parseString.startsWith("0B")) {
				parseString = string.substring(2);
				radix=2;
			}
			return new BigInteger(parseString,radix);
		} catch (NumberFormatException e) {
			throw new ValueConverterException("Couldn't convert '" + string + "' to a BigInteger value.", node, e);
		}
	}

}
