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

class ConditionalHelper {
    private boolean inif;
    private boolean sawelse;
    private boolean handled;
    private boolean copy;

    ConditionalHelper(boolean inif, boolean sawelse, boolean handled,
            boolean copy) {
        this.inif = inif;
        this.sawelse = sawelse;
        this.handled = handled;
        this.copy = copy;
    }

    boolean isInif() {
        return inif;
    }

    void setInif(boolean inif) {
        this.inif = inif;
    }

    boolean isSawelse() {
        return sawelse;
    }

    void setSawelse(boolean sawelse) {
        this.sawelse = sawelse;
    }

    boolean isHandled() {
        return handled;
    }

    void setHandled(boolean handled) {
        this.handled = handled;
    }

    boolean isCopy() {
        return copy;
    }

    void setCopy(boolean copy) {
        this.copy = copy;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(inif ? "inif" : "!inif");
        sb.append(":");
        sb.append(sawelse ? "sawelse" : "!sawelse");
        sb.append(":");
        sb.append(handled ? "handled" : "!handled");
        sb.append(":");
        sb.append(copy ? "copy" : "!copy");
        sb.append("}");
        return sb.toString();
    }
}
