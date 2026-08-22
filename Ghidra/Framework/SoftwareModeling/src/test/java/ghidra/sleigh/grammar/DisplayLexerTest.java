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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.antlr.runtime.ANTLRStringStream;
import org.antlr.runtime.Token;
import org.junit.Test;

public class DisplayLexerTest {

  @Test
  public void testDollarOperatorPrefixesAreIdentifiers() throws IOException {
    assertDisplayTokens("$anderson",
      new int[] { DisplayLexer.DISPCHAR, DisplayLexer.IDENTIFIER },
      new String[] { "$", "anderson" });
    assertDisplayTokens("$orphan",
      new int[] { DisplayLexer.DISPCHAR, DisplayLexer.IDENTIFIER },
      new String[] { "$", "orphan" });
    assertDisplayTokens("$xorValue",
      new int[] { DisplayLexer.DISPCHAR, DisplayLexer.IDENTIFIER },
      new String[] { "$", "xorValue" });
  }

  @Test
  public void testDollarPrefixedDisplayIdentifierMatchesExistingTokenization()
      throws IOException {
    assertDisplayTokens("!$jumpAddressAbsolute is",
      new int[] { DisplayLexer.EXCLAIM, DisplayLexer.DISPCHAR, DisplayLexer.IDENTIFIER,
        DisplayLexer.WS, DisplayLexer.RES_IS },
      new String[] { "!", "$", "jumpAddressAbsolute", " ", "is" });
    assertDisplayTokens("!$absoluteJumpAddress is",
      new int[] { DisplayLexer.EXCLAIM, DisplayLexer.DISPCHAR, DisplayLexer.IDENTIFIER,
        DisplayLexer.WS, DisplayLexer.RES_IS },
      new String[] { "!", "$", "absoluteJumpAddress", " ", "is" });
  }

  private static void assertDisplayTokens(String input, int[] expectedTypes,
      String[] expectedTexts) throws IOException {
    assertEquals("Expected token type/text counts", expectedTypes.length, expectedTexts.length);

    LineArrayListWriter writer = new LineArrayListWriter();
    writer.write(input.toCharArray(), 0, input.length());
    ParsingEnvironment env = new ParsingEnvironment(writer);
    DisplayLexer lexer = new DisplayLexer(new ANTLRStringStream(input));
    lexer.setEnv(env);

    for (int i = 0; i < expectedTypes.length; i++) {
      Token token = lexer.nextToken();
      assertEquals(input, expectedTypes[i], token.getType());
      assertEquals(input, expectedTexts[i], token.getText());
    }

    assertEquals(input, Token.EOF, lexer.nextToken().getType());
    assertEquals(input, 0, env.getLexingErrors());
  }
}
