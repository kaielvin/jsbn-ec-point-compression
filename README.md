jsbn-ec-point-compression
=========================

Extension of Elliptic Curve implementation from library JSBN (http://www-cs-students.stanford.edu/~tjw/jsbn/) to support compression and decompression of EC points.

Like the original JSBN, the extension has been ported loosely from BouncyCastle's Java EC code.

Dependencies from the JSBN library are : jsbn.js, jsbn2.js, rng.js and ec.js.

```
## Usage :

var curve = getSECCurveByName("secp256r1").getCurve(); // from sec.js

var compressed = "028bd9aaec3783a891b4d4707004b265715651a6a78f6a43b30c2b51d0b63052d8";
var decompressed = curve.decodePointHex(compressed); // of type ECPointFp
compressed = curve.encodeCompressedPointHex(decompressed);
decompressed = curve.decodePointHex(compressed);

console.log(compressed);
console.log(curve.encodePointHex(decompressed)); // uncompressed hex encoding

## Output :

028bd9aaec3783a891b4d4707004b265715651a6a78f6a43b30c2b51d0b63052d8
048bd9aaec3783a891b4d4707004b265715651a6a78f6a43b30c2b51d0b63052d8306c2f9a7c4cc6965b0701d0a22b5c00fc812322385b0ac91483a34d7bd88724
 
```
