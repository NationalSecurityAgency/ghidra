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
package ghidra.sleigh.grammar;

import java.io.*;

import org.antlr.runtime.*;
import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class BooleanExpressionDefTest extends AbstractGenericTest {

    public BooleanExpressionDefTest() {
        super();
    }

    BooleanExpressionParser parser;
    Reader reader;

    private void initParser(Reader theReader) throws IOException {
        this.reader = theReader;
        CharStream charStream = new ANTLRReaderStream(theReader);
        BooleanExpressionLexer lexer = new BooleanExpressionLexer(charStream);
        CommonTokenStream tokenStream = new CommonTokenStream(lexer);
        parser = new BooleanExpressionParser(tokenStream);
        parser.env = new ExpressionEnvironment() {
            public boolean equals(String lhs, String rhs) {
                if (lhs == null || rhs == null) {
                    return false;
                }
                return lhs.equals(rhs);
            }

            public String lookup(String variable) {
                if (variable.startsWith("A")) {
                    return variable;
                }
                return null;
            }

			@Override
			public void reportError(String msg) {
				// Don't do anything for test
			}
        };
    }

@Test
    public void testSimplePositive() throws Exception {
        initParser(new StringReader("defined(Astar)"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testSimpleNegative() throws Exception {
        initParser(new StringReader("defined(Bstar)"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testPrecedence() throws Exception {
        initParser(new StringReader("defined(Afoo) && !(defined(Bfoo))"));
        Assert.assertEquals(true, parser.expression());
    }
}
