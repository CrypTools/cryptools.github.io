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

class Ciphers {
    constructor() {
        this.select  = document.querySelector('#ciphers .demo select')
        this.cipher  = this.select.value
        document.getElementById(this.cipher).classList.add('active')

		this.controller = {}

		this.swap()

    }

    swap() {
		document.getElementById(this.cipher).classList.remove('active')
		this.cipher = this.select.value
		document.getElementById(this.cipher).classList.add('active')

		this.controller = {}

		let inputs = document.getElementById(this.cipher).querySelectorAll("input")

		let placeholders = []

		for (let i = 0; i < inputs.length; i++) {
			placeholders.push(inputs[i].placeholder)

			inputs[i].placeholder = "Loading..."
			inputs[i].disabled = true
		}

		this.load(ciphers[this.cipher]).then(data => {
			this.controller = data

			this.listener()

			for (let i = 0; i < inputs.length; i++) {
				inputs[i].placeholder = placeholders[i]
				inputs[i].disabled = false
				inputs[i].readonly = false
			}
		})
    }
	load(c) {
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

	listener() {
		let inputs = document.getElementById(this.cipher).querySelectorAll("input")

		const render = e => {
			if (e) {
				e.preventDefault()
			}
			let args = []
			for (let i = 0; i < inputs.length; i++) {
				if (inputs[i].type == "number") {
					args.push(parseFloat(inputs[i].value))
				} else {
					args.push(inputs[i].value)
				}

			}

			let msg = document.querySelectorAll(".large > input")

			for (let i = 0; i < msg.length; i++) {
				msg[i].value = args[0]
			}

			const rendered = this.controller.encrypt(...args)
			document.querySelector("#output > pre").innerHTML = rendered
		}

		for (let i of inputs) {
			i.addEventListener("change", render)
			// i.addEventListener("keydown", render)
			i.addEventListener("input", render)
			i.addEventListener("paste", render)
		}
		render() // Will render old values
	}
}

c = new Ciphers()
