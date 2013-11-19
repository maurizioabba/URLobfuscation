apache module for obfuscation of URL when visited by a search engine robot
It uses meta canonical tag, and write in it the obfuscated URL. When the search engine robot is visiting the page, the tag make him save the page with the url found inside the canonical, obtaining an obfuscated URL (right now obfuscation is performed by XORing the URL with a fixed key repeated, can change in the future but it's not fundamental for security reasons).
If a visitor (not a robot) clicks on the URL coming from a search, the obfuscated url will be deobfuscated and the correct page will be displayed.
Using this tag allows for the module to be completely indipendent by the pages present on the server.
