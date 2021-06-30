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
package ghidra.util.config;

import java.awt.*;

public class ColorHexConvert {
    /**
     * Color Object converts to String
     * @param color Color Object
     * @return Hex Color String
     * */
    private static String toHexFromColor(Color color){
        String r,g,b;
        StringBuilder su = new StringBuilder();
        r = Integer.toHexString(color.getRed());
        g = Integer.toHexString(color.getGreen());
        b = Integer.toHexString(color.getBlue());
        r = r.length() == 1 ? "0" + r : r;
        g = g.length() ==1 ? "0" +g : g;
        b = b.length() == 1 ? "0" + b : b;
        r = r.toUpperCase();
        g = g.toUpperCase();
        b = b.toUpperCase();
        su.append("0xFF");
        su.append(r);
        su.append(g);
        su.append(b);
        return su.toString();
    }
    /**
     * String converts to Color Object
     * @param colorStr Hex Color String
     * @return Color Object
     * */
    public static Color toColorFromString(String colorStr){
        if (colorStr.length() == 7){
            colorStr = colorStr.replace("#","0xff");
        }
        else if (colorStr.length() == 9){
            colorStr = colorStr.replace("#","0x");
        }
        else{
            colorStr = "#ff000000";
        }
        colorStr = colorStr.substring(4);
        Color color =  new Color(Integer.parseInt(colorStr, 16)) ;
        return color;
    }
}
