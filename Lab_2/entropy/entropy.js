const fs = require('fs')
const len = 256

function calcFileEntropy(filePath) {
    let fileData = fs.readFileSync(filePath).toString('hex')
    let n = new Array(len).fill(0)
    let f = new Array(len).fill(0)
    let numberOfBytes = fileData.length / 2
    let result = 0

    for (let i = 0; i < fileData.length; i += 2) {
        currNumber = parseInt((fileData[i] + '' + fileData[i + 1]), 16)
        n[currNumber] += 1
    }

    for (let i = 0; i < len; i++) {
        currFrequency = n[i] / numberOfBytes
        if (currFrequency !== 0)
            result += currFrequency * Math.log2(currFrequency)
    }

    return (-1) * result;
}

console.log('plain af: ', calcFileEntropy('./plain'))
console.log('plain ger: ', calcFileEntropy('./plain_ger'))
console.log('plain nl: ', calcFileEntropy('./plain_nl'))
console.log('cipher: ', calcFileEntropy('../itsec-secret-key-crypto/cipher'))
console.log('decrypted: ', calcFileEntropy('../itsec-secret-key-crypto/decrypted'))
console.log('mystery: ', calcFileEntropy('../itsec-secret-key-crypto/mystery'))
// console.log('FileEncrypter: ', calcFileEntropy('../itsec-secret-key-crypto/src/main/java/ch/zhaw/its/lab/secretkey/FileEncrypter.java'))
