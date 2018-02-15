---
---

const ciphers = {{site.data.ciphers | jsonify}}
var ciphersFile = []

for (var i in ciphers) {
    ciphersFile.push(['/'+i.github+'/js/encrypt.js', '/'+i.github+'/js/decrypt.js'])
}

console.log(ciphersFile)
