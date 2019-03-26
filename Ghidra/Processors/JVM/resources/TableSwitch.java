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
class TableSwitch{

    
    public int zeroBytesPadding(int x){
        int y = 1;
        switch(x){
        case 0:
            y = 1;
            break;
        case 1:
            y = 2;
            break;
        case 2:
            y = 3;
            break;
        default:
            y=4;
        }
        return y;
    }

    public int oneBytePadding(int x){
        int y = 0;
        y++; 
        switch(x){
        case 0:
            y = 1;
            break;
        case 1:
            y = 2;
            break;
        case 2:
            y = 3;
            break;
        default:
            y=4;
        }
        return y;
    }

    public int twoBytesPadding(int x){
        int y;
        switch(x){
        case 0:
            y = 1;
            break;
        case 1:
            y = 2;
            break;
        case 2:
            y = 3;
            break;
        default:
            y=4;
        }
        return y;
    }

    public int threeBytesPadding(int x){
        int y = 8;
        switch(x){
        case 0:
            y = 1;
            break;
        case 1:
            y = 2;
            break;
        case 2:
            y = 3;
            break;
        default:
            y=4;
        }
        return y;
    }

}
