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

public class BooleanExpressionTest extends AbstractGenericTest {

    public BooleanExpressionTest() {
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
                return variable;
            }

			@Override
			public void reportError(String msg) {
				// Don't do anything for test
			}
        };
    }

@Test
    public void testEquals1() throws Exception {
        initParser(new StringReader("FOO == \"FOO\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testEquals2() throws Exception {
        initParser(new StringReader("FOO == FOO"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testEquals3() throws Exception {
        initParser(new StringReader("\"FOO\" == \"FOO\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testEquals4() throws Exception {
        initParser(new StringReader("\"FOO\" == FOO"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testEqualsInv1() throws Exception {
        initParser(new StringReader("FOO == \"BAR\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testEqualsInv2() throws Exception {
        initParser(new StringReader("FOO == BAR"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testEqualsInv3() throws Exception {
        initParser(new StringReader("\"FOO\" == \"BAR\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testEqualsInv4() throws Exception {
        initParser(new StringReader("\"FOO\" == BAR"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotEquals1() throws Exception {
        initParser(new StringReader("FOO != \"FOO\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotEquals2() throws Exception {
        initParser(new StringReader("FOO != FOO"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotEquals3() throws Exception {
        initParser(new StringReader("\"FOO\" != \"FOO\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotEquals4() throws Exception {
        initParser(new StringReader("\"FOO\" != FOO"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotEqualsInv1() throws Exception {
        initParser(new StringReader("FOO != \"BAR\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testNotEqualsInv2() throws Exception {
        initParser(new StringReader("FOO != BAR"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testNotEqualsInv3() throws Exception {
        initParser(new StringReader("\"FOO\" != \"BAR\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testNotEqualsInv4() throws Exception {
        initParser(new StringReader("\"FOO\" != BAR"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testSimpleParens() throws Exception {
        initParser(new StringReader("(FOO == FOO)"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testMoreParens() throws Exception {
        initParser(new StringReader("((((FOO == FOO))))"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testNot() throws Exception {
        initParser(new StringReader("!(FOO == FOO)"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testNotInv() throws Exception {
        initParser(new StringReader("!(FOO != FOO)"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testMoreNots() throws Exception {
        initParser(new StringReader("!(!(!(FOO == FOO)))"));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testEvenMoreNots() throws Exception {
        initParser(new StringReader("!(!(!(!(FOO == FOO))))"));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testOr1() throws Exception {
        initParser(new StringReader("FOO == \"FOO\" || BAR == \"BAR\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testOr2() throws Exception {
        initParser(new StringReader("FOO == \"BAR\" || BAR == \"BAR\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testOr3() throws Exception {
        initParser(new StringReader("FOO == \"FOO\" || BAR == \"FOO\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testOr4() throws Exception {
        initParser(new StringReader("FOO == \"BAR\" || BAR == \"FOO\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testAnd1() throws Exception {
        initParser(new StringReader("FOO == \"FOO\" && BAR == \"BAR\""));
        Assert.assertEquals(true, parser.expression());
    }

@Test
    public void testAnd2() throws Exception {
        initParser(new StringReader("FOO == \"BAR\" && BAR == \"BAR\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testAnd3() throws Exception {
        initParser(new StringReader("FOO == \"FOO\" && BAR == \"FOO\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testAnd4() throws Exception {
        initParser(new StringReader("FOO == \"BAR\" && BAR == \"FOO\""));
        Assert.assertEquals(false, parser.expression());
    }

@Test
    public void testComplicated() throws Exception {
        String test = "!(A!=\"A\" || B==\"B\" ^^ (C!=\"C\" || D==\"D\") && E!=\"E\")";
        initParser(new StringReader(test));
        Assert.assertEquals(false, parser.expression());
    }
}
