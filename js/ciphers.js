---
---
/***********************************************

Use:
	ciphers: list of all url
	load:
		load(ciphers.XORCipher).then(data => {
			console.log(data.encrypt("Hello world!", 134))
		})

***********************************************/

const CiphersData = {{site.data.ciphers | jsonify}}

let ciphers = {}

for (let i of CiphersData) {
    ciphers[i.github] = ['https://cryptools.github.io/'+i.github+'/js/encrypt.js', 'https://cryptools.github.io/'+i.github+'/js/decrypt.js']
}

function load(c) {
	return new Promise((resolve, reject) => {
		let encrypt = () => {}
		let decrypt = () => {}
		fetch(c[0]).then(data => data.text()).then(data => {
			let module = {
				exports: null
			}
			eval(data)
			encrypt = module.exports
			fetch(c[1]).then(data => data.text()).then(data => {
				let module = {
					exports: null
				}
				eval(data)
				decrypt = module.exports
				resolve({
					encrypt: encrypt,
					decrypt: decrypt
				})
			})
		})
	})
}

class Ciphers {
    constructor() {
        this.select  = document.querySelector('#ciphers .demo select')
        this.cipher  = this.select.value
        document.getElementById(this.cipher).classList.add('active')

        this.swap    = this.swap.bind(this)
    }

    swap() {
        if (this.cipher != this.select.value) {

            document.getElementById(this.cipher).classList.remove('active')
            this.cipher = this.select.value
            document.getElementById(this.cipher).classList.add('active')

        }
    }
}

c = new Ciphers()
