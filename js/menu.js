class Menu {
    constructor() {
        this.state  = false
        this.toggle = document.getElementById('menu-toggle')
        this.links  = document.querySelectorAll('nav ul a')
        this.ul     = document.querySelector('nav ul')

        this.open   = this.open.bind(this)
        this.close  = this.close.bind(this)
        this.swap   = this.swap.bind(this)

        this._addEventListeners()
    }

    _addEventListeners() {
        this.links.forEach(l => l.addEventListener('click', this.close))
        this.toggle.addEventListener('click', this.swap)
        window.addEventListener('scroll', this.close)
        window.addEventListener('resize', this.close)
    }

    open() {
        this.ul.classList.add('active')
        this.state = true
    }

    close() {
        this.ul.classList.remove('active')
        this.state = false
    }

    swap() {
        if (this.state == true) this.close()
        else if (this.state == false) this.open()
    }
}

var m = new Menu()
