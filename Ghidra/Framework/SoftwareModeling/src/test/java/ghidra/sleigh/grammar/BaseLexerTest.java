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

public class BaseLexerTest {

  @Test
  public void testDollarBooleanOperators() throws IOException {
    assertTokens("$and", BaseLexer.SPEC_AND);
    assertTokens("$or", BaseLexer.SPEC_OR);
    assertTokens("$xor", BaseLexer.SPEC_XOR);
  }

  private static void assertTokens(String input, int expectedType) throws IOException {
    LineArrayListWriter writer = new LineArrayListWriter();
    writer.write(input.toCharArray(), 0, input.length());
    ParsingEnvironment env = new ParsingEnvironment(writer);
    BaseLexer lexer = new BaseLexer(new ANTLRStringStream(input));
    lexer.setEnv(env);

    Token token = lexer.nextToken();
    assertEquals(input, expectedType, token.getType());
    assertEquals(input, input, token.getText());
    assertEquals(input, Token.EOF, lexer.nextToken().getType());
    assertEquals(input, 0, env.getLexingErrors());
  }
}
