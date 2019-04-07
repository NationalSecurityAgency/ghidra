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
package ghidra.app.util.exporter;

import ghidra.program.model.address.Address;

abstract class AbstractLineDispenser {

    protected boolean isHTML = false;
    protected int width = 0;
    protected int fillAmount = 0;
    protected String prefix;
    protected int index = 0;

    abstract boolean hasMoreLines();

    abstract String getNextLine();

    abstract void dispose();

    static String getUniqueAddressString(Address addr) {
        return addr.toString();
        /*
        return  addr.getAddressSpace().getSpaceID() + "_" +
                addr.getOverlayId() + "_" +
                addr.getOffset() + "_";
                */
    }

    static String getFill(int amt){
        StringBuffer fill = new StringBuffer();
        for (int i = 0 ; i < amt ; ++i) {
            fill.append(" ");
        }
        return fill.toString();
    }

    String getFill(){
        int amt = fillAmount + (hasMoreLines() ? 0 : width);
        return getFill(amt);
    }

    static String clip(String s, int width) {
        return clip(s,width,true,true);
    }

    static String clip(String s, int width, boolean padIfShorter, boolean leftJustify) {
        if (width < 0) return "";

        //if length of s is less than len,
        //then we need to pad it...
        if (s.length() <= width) {
            if (leftJustify) {
                return s + (padIfShorter ? getFill(width - s.length()) : "");
            }
            return (padIfShorter ? getFill(width - s.length()) : "") + s;
        }

        switch (width) {
            case 0: return "";
            case 1: return ".";
            case 2: return "..";
            case 3: return "...";
            default: return s.substring(0, width - 3) + "...";
        }
    }

}
