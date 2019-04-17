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
class LookupSwitchHex{
    
    public int zeroBytesPadding(int x){
        int y = 1;
        switch(x){
        case 0:
            y = 0;
            break;
        case 0x10:
            y = 1;
            break;
        case 0x20:
            y = 2;
            break;
        case 0x100:
            y = 3;
            break;
        case 0x200:
            y=4;
            break;
        case 0x1000:
            y=5;
            break;
        case 0x2000:
            y=6;
            break;
        case 0x10000:
          y=7;
          break;
        case 0x20000:
          y=8;
          break;
        default:
            y=9;
           break;
        }
        return y;
    }


    public int oneBytesPadding(int x){
        int y = 1;
        y++;
        switch(x){
        case 0:
            y = 0;
            break;
        case 0x10:
            y = 1;
            break;
        case 0x20:
            y = 2;
            break;
        case 0x100:
            y = 3;
            break;
        case 0x200:
            y=4;
            break;
        case 0x1000:
            y=5;
            break;
        case 0x2000:
            y=6;
            break;
        case 0x10000:
          y=7;
          break;
        case 0x20000:
          y=8;
          break;
        default:
            y=9;
           break;
        }
        return y;
    }

}
