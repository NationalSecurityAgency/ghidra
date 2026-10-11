# HexToCode

כלי להנדסה לאחור (Reverse Engineering) בעברית, עם עוזר AI מובנה. מבוסס על Ghidra.
Copyright (c) 2026 שמואל סיני (Shmuel Sinay) <g47ben@gmail.com>. כל הזכויות שמורות.

## מה כלול

* **ממשק מלא בעברית**: תפריטים, חלונות, כפתורים, הגדרות ותיאורי כלים. תפריטים מימין לשמאל.
* **עוזר AI מובנה** (חלון > עוזר AI):
  * עונה בעברית על שאלות כמו "איפה נבדקת הסיסמה?" או "מה גורם לשגיאה הזו?". העוזר
    חוקר את התוכנית בעצמו ומעביר אותך למקום הנכון.
  * ממליץ על קוד מת ועל דברים שאפשר למחוק או לנטרל.
  * עורך באישורך: שינוי שמות, חתימות, הערות בעברית, Patch, מחיקת פונקציות. כל שינוי
    אפשר לבטל עם Ctrl+Z.
  * "תעד הכל בעברית": כותב הערה בעברית מעל כל פונקציה.
  * ייצוא קובץ מתוקן שאפשר להריץ, וייצוא כל הקוד ל-C.
  * ספקים: Anthropic Claude, Google AI Studio (Gemini), וכל שירות שתואם ל-OpenAI
    (OpenAI, OpenRouter, DeepSeek, Ollama, LM Studio ועוד).

## הורדה והתקנה

יש שני סוגי הורדות:

| קובץ | למי | צריך Java? |
|---|---|---|
| `HexToCode-<גרסה>-windows-with-java.zip` | Windows | **לא**, Java כלולה בפנים |
| `HexToCode-<גרסה>-linux-with-java.zip` | Linux | **לא**, Java כלולה בפנים |
| `HexToCode-<גרסה>-macos-with-java.zip` | macOS | **לא**, Java כלולה בפנים |
| `HexToCode-<גרסה>.zip` | כל המערכות, קובץ קטן יותר | כן, JDK 25 ([Adoptium](https://adoptium.net)) |

1. הורד את הקובץ המתאים ופתח אותו לתיקייה.
2. הפעל את `HexToCode.bat` (Windows) או את `./HexToCode` (Linux/macOS).
3. לעוזר ה-AI: עריכה > אפשרויות הכלי > עוזר AI. בחר ספק והדבק מפתח API.

אפשר לוודא שההורדה תקינה לפי הקובץ `HexToCode-<גרסה>.sha256`.

## רישיון

HexToCode מופץ תחת רישיון שימוש מוגבל (`LICENSE`): מותר להוריד, להתקין ולהריץ לשימוש עצמי.
כל שימוש אחר, כמו הפצה, שינוי או שימוש מסחרי, דורש אישור בכתב.
רכיבי Ghidra ורכיבי צד שלישי נשארים תחת הרישיונות שלהם (Apache 2.0, GPL ועוד). ראה `NOTICE`
ואת התיקייה `licenses` בחבילה.
HexToCode אינו קשור ל-NSA או לספקי ה-AI, ולא מקבל מהם חסות.

---

**English:** HexToCode is a Hebrew-language reverse engineering tool with a built-in AI
assistant, based on Ghidra. The `-with-java` packages include Java; the all-platform package
requires JDK 25. Run `HexToCode.bat` (Windows) or `HexToCode` (Linux/macOS). Licensed under the HexToCode Restricted License (see LICENSE); Ghidra and
other third-party components keep their own licenses.
