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
package ghidra.app.util.exporter;

import ghidra.program.model.listing.Variable;
import ghidra.util.StringUtilities;

class CommentLineDispenser extends AbstractLineDispenser {

    private String [] comments;

    CommentLineDispenser(Variable var, int width, int fillAmount, String prefix) {
        this.comments = StringUtilities.toLines(var.getComment());
        this.width = width;
        this.fillAmount = fillAmount;
    }

    @Override
    boolean hasMoreLines() {
        return (index < comments.length);
    }

    @Override
    String getNextLine() {
        if (hasMoreLines()) {
            return clip(comments[index++], width);
        }
        return null;
    }


    @Override
    void dispose() {
    }

}
