/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.io.IOException;
import org.antlr.runtime.EarlyExitException;
import org.antlr.runtime.FailedPredicateException;
import org.antlr.runtime.MismatchedNotSetException;
import org.antlr.runtime.MismatchedSetException;
import org.antlr.runtime.MismatchedTokenException;
import org.antlr.runtime.MismatchedTreeNodeException;
import org.antlr.runtime.MissingTokenException;
import org.antlr.runtime.NoViableAltException;
import org.antlr.runtime.RecognitionException;
import org.antlr.runtime.Token;
import org.antlr.runtime.UnwantedTokenException;

public class BaseRecognizerOverride {
    static final String NEWLINE = System.getProperty("line.separator");

    public String getErrorMessage(RecognitionException e, String[] tokenNames, LineArrayListWriter writer) {
        String msg = e.getMessage();
        if (e instanceof UnwantedTokenException) {
            UnwantedTokenException ute = (UnwantedTokenException) e;
            String tokenName = "<unknown>";
            if (ute.expecting == Token.EOF) {
                tokenName = "EOF";
            } else {
                if (tokenNames != null) {
                    tokenName = tokenNames[ute.expecting];
                }
            }
            msg = "extraneous input "
                    + getTokenErrorDisplay(ute.getUnexpectedToken())
                    + " expecting " + tokenName;
        } else if (e instanceof MissingTokenException) {
            MissingTokenException mte = (MissingTokenException) e;
            String tokenName = "<unknown>";
            if (mte.expecting == Token.EOF) {
                msg = "unexpected token: " + getTokenErrorDisplay(e.token);
            } else {
                msg = "missing " + tokenName + " at "
                        + getTokenErrorDisplay(e.token);
            }
        } else if (e instanceof MismatchedTokenException) {
            msg = "unexpected token: " + getTokenErrorDisplay(e.token);
        } else if (e instanceof MismatchedTreeNodeException) {
            MismatchedTreeNodeException mtne = (MismatchedTreeNodeException) e;
            String tokenName = "<unknown>";
            if (mtne.expecting == Token.EOF) {
                tokenName = "EOF";
            } else {
                if (tokenNames != null) {
                    tokenName = tokenNames[mtne.expecting];
                }
            }
            msg = "mismatched tree node: " + mtne.node + " expecting "
                    + tokenName;
        } else if (e instanceof NoViableAltException) {
            msg = "unexpected token: " + getTokenErrorDisplay(e.token);
        } else if (e instanceof EarlyExitException) {
            // EarlyExitException eee = (EarlyExitException)e;
            // for development, can add "(decision="+eee.decisionNumber+")"
            msg = "required (...)+ loop did not match anything at input "
                    + getTokenErrorDisplay(e.token);
        } else if (e instanceof MismatchedSetException) {
            MismatchedSetException mse = (MismatchedSetException) e;
            msg = "mismatched input " + getTokenErrorDisplay(e.token)
                    + " expecting set " + mse.expecting;
        } else if (e instanceof MismatchedNotSetException) {
            MismatchedNotSetException mse = (MismatchedNotSetException) e;
            msg = "mismatched input " + getTokenErrorDisplay(e.token)
                    + " expecting set " + mse.expecting;
        } else if (e instanceof FailedPredicateException) {
            FailedPredicateException fpe = (FailedPredicateException) e;
            msg = "rule " + fpe.ruleName + " failed predicate: {"
                    + fpe.predicateText + "}?";
        }
        String line = "<internal error fetching line>";
        try {
            line = ANTLRUtil.getLine(writer, e.line);
        }
        catch (IOException e1) {
            e1.printStackTrace();
        }
        int position = ANTLRUtil.tabCompensate(line, e.charPositionInLine);
        return msg + ":" + NEWLINE + NEWLINE
                + line + NEWLINE
                + ANTLRUtil.generateArrow(position);
    }

    public String getTokenErrorDisplay(Token t) {
        String s = t.getText();
        if (s == null) {
            if (t.getType() == Token.EOF) {
                s = "<EOF>";
            } else {
                s = "<" + t.getType() + ">";
            }
        }
        s = s.replaceAll("\n", "\\\\n");
        s = s.replaceAll("\r", "\\\\r");
        s = s.replaceAll("\t", "\\\\t");
        return "'" + s + "'";
    }
}
